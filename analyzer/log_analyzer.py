import argparse
import os
import sys
import re
import xml.etree.ElementTree as ET

from windows_rules import rules as windows_rules
from linux_rules import rules as linux_rules
from colorama import init, Fore, Style
from comments import *
from exporter_json import exporter_resultats_json

init(autoreset=True)

resultats = []  # Pour l'export final

# Pour colorer les ip en bleu
def print_color(line):
    ip_pattern = r'(\b(?:\d{1,3}\.){3}\d{1,3}\b)'

    # Si on trouve une ou plusieurs IP dans la ligne, on colore uniquement ces IP en bleu
    if re.search(ip_pattern, line):
        def repl(match):
            return f"{Fore.BLUE}{match.group(0)}{Style.RESET_ALL}"
        colored_line = re.sub(ip_pattern, repl, line)
        print(colored_line)
    else:
        print(line)


# Import pour les logs EVTX (Windows)
try:
    from Evtx.Evtx import Evtx
except ImportError:
    Evtx = None
    print("⚠️ Module python-evtx non trouvé. Installe-le avec 'pip install python-evtx' pour analyser les logs Windows EVTX.")

# ─────────────────────────────────────────
# ANALYSE DE LOGS LINUX (auth.log / secure)
# ─────────────────────────────────────────
def analyze_linux_log(filepath):
    """
    Analyse un fichier de log Linux.
    Détecte : connexions SSH réussies ou échouées, utilisation de sudo ou commande root.
    """
    if not os.path.isfile(filepath):
        print(f"Erreur : le fichier {filepath} n'existe pas.")
        return
    
    print(f"\n--- Analyse du fichier Linux : {filepath} ---")

    events_found = False

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            for rule in linux_rules:
                if rule["match"](line):
                    label_colored = f"{rule['color']}{rule['label']}{Style.RESET_ALL}"
                    if rule["show_line"]:
                        print_color(f"{label_colored} {line.strip()}")
                    else:
                        print_color(label_colored)

                    # Extraction précise selon le type de log
                    try:
                        timestamp = line[:15].strip()
                        programme_match = re.search(r"(\w+)\[\d+\]:", line)
                        programme = programme_match.group(1) if programme_match else "Inconnu"

                        utilisateur = "-"
                        if "Failed password for" in line or "Accepted password for" in line:
                            match_user = re.search(r"(?:invalid user )?(\w+) from", line)
                            utilisateur = match_user.group(1) if match_user else "-"
                        elif "sudo:" in line:
                            match_user = re.search(r"sudo:\s+(\w+)", line)
                            utilisateur = match_user.group(1) if match_user else "-"
                        elif "su:" in line:
                            match_user = re.search(r"su:\s+(\w+)", line)
                            utilisateur = match_user.group(1) if match_user else "-"

                        resultats.append({
                            "timestamp": timestamp,
                            "programme": programme,
                            "utilisateur": utilisateur,
                            "description": rule["label"],
                            "ligne_complete": line.strip()
                        })

                    except Exception as e:
                        print(f"Erreur d'extraction : {e}")

                    events_found = True
                    break  # Une règle a matché, on passe à la ligne suivante
    
    if not events_found:
        print("Aucun événement notable détecté dans ce fichier.")
    else:
        print("✅ Analyse Linux terminée avec succès.")
    
    return resultats

# ──────────────────────────────────────
# ANALYSE DE LOGS WINDOWS (fichiers .evtx)
# ──────────────────────────────────────

def analyze_windows_log(filepath):

    if Evtx is None:
        print("Erreur : impossible d'analyser les logs Windows sans le module python-evtx.")
        return
    
    if not os.path.isfile(filepath):
        print(f"Erreur : le fichier {filepath} n'existe pas.")
        return
    
    print(f"\n--- Analyse du fichier Windows EVTX : {filepath} ---")
    events_found = False

    try:
        with Evtx(filepath) as log:
            for record in log.records():
                xml_str = record.xml()
                
                try:
                    root = ET.fromstring(xml_str)
                    ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

                    # Infos système générales
                    event_id = root.find('.//ns:EventID', ns).text.strip()
                    timestamp = root.find('.//ns:TimeCreated', ns).attrib['SystemTime']
                    computer_name = root.find('.//ns:Computer', ns).text

                    # Infos utilisateur
                    subject_username = root.find('.//ns:Data[@Name="SubjectUserName"]', ns).text
                    domain = root.find('.//ns:Data[@Name="SubjectDomainName"]', ns).text
                    logon_id = root.find('.//ns:Data[@Name="SubjectLogonId"]', ns).text
                    
                    if event_id is not None:
                        for rule in windows_rules:
                            if str(rule['event_id']) == event_id:
                                print(f"{rule['color']}{rule['label']}{Style.RESET_ALL}")
                                if rule["show_line"]:
                                    print(f"[{timestamp}] Event ID {event_id} - {subject_username}@{domain} sur {computer_name} (Logon ID: {logon_id})")
                                    resultats.append({
                                        "event_id": event_id,
                                        "description": rule['label'],
                                        "utilisateur": subject_username,
                                        "domaine": domain,
                                        "ordinateur": computer_name,
                                        "horodatage": timestamp,
                                        "logon_id": logon_id
                                    })

                                events_found = True
                                break
                except ET.ParseError:
                    print("[!] Impossible de parser un événement.")

        if not events_found:
            print("Aucun événement notable détecté dans ce fichier.")
        else:
            print("✅ Analyse Windows terminée avec succès.")

    except Exception as e:
        print(f"Erreur lors de la lecture du fichier EVTX : {e}")

    return resultats


# ─────────────────────
# Détection auto du type
# ─────────────────────
def detect_log_type(filepath):
    """
    Détecte automatiquement le type de log à partir de l'extension.
    """
    if not os.path.isfile(filepath):
        print(f"Erreur : le fichier {filepath} n'existe pas.")
        return None
    
    ext = os.path.splitext(filepath)[1].lower()
    
    if ext == ".evtx":
        return "windows"
    else:
        # Tentative simple : si le fichier est lisible en texte, on considère Linux
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                f.read(1024)
            return "linux"
        except UnicodeDecodeError:
            return None

# ──────────────
# CLI principale
# ──────────────
def main():
    parser = argparse.ArgumentParser(description="Analyse automatique de logs Linux et Windows.")
    parser.add_argument("--file", required=True, help="Chemin vers le fichier log à analyser")
    args = parser.parse_args()

    log_type = detect_log_type(args.file)
    
    if log_type == "linux":
        # analyze_linux_log(args.file)
        resultats = analyze_linux_log(args.file)
        exporter_resultats_json(resultats, "linux")
    elif log_type == "windows":
        # analyze_windows_log(args.file)
        resultats = analyze_windows_log(args.file)
        exporter_resultats_json(resultats, "windows")
    else:
        print("❌ Impossible de détecter le type de log ou format non supporté.")

if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        comment_error("Arrêt du script demandé par l'utilisateur.")
