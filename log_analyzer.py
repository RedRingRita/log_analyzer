import argparse
import os
import sys
import re
import windows_rules

from linux_rules import rules as linux_rules
from colorama import init, Fore, Style

init(autoreset=True)

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
                    events_found = True
                    break  # Si une règle matche, on ne teste pas les autres pour cette ligne
    
    if not events_found:
        print("Aucun événement notable détecté dans ce fichier.")
    else:
        print("✅ Analyse Linux terminée avec succès.")

# ──────────────────────────────────────
# ANALYSE DE LOGS WINDOWS (fichiers .evtx)
# ──────────────────────────────────────
def analyze_windows_log(filepath):
    """
    Analyse un fichier de log EVTX Windows.
    Détecte : connexions réussies (4624), échouées (4625), élévations de privilèges (4672).
    """
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

                # Échec de connexion (Event ID 4625)
                if "EventID>4625<" in xml_str:
                    print("[ECHEC CONNEXION WINDOWS] Event ID 4625")
                    events_found = True

                # Connexion réussie (Event ID 4624)
                elif "EventID>4624<" in xml_str:
                    print("[CONNEXION WINDOWS REUSSIE] Event ID 4624")
                    events_found = True

                # Connexion réussie (Event ID 4624)
                elif "EventID>4634<" in xml_str:
                    print("[DECONNEXION WINDOWS REUSSIE] Event ID 4634")
                    events_found = True

                # Élévation de privilèges (Event ID 4672)
                elif "EventID>4672<" in xml_str:
                    print("[ELEVATION DE PRIVILEGES] Event ID 4672")
                    events_found = True
        
        if not events_found:
            print("Aucun événement notable détecté dans ce fichier.")
        else:
            print("✅ Analyse Windows terminée avec succès.")

    except Exception as e:
        print(f"Erreur lors de la lecture du fichier EVTX : {e}")

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
        analyze_linux_log(args.file)
    elif log_type == "windows":
        analyze_windows_log(args.file)
    else:
        print("❌ Impossible de détecter le type de log ou format non supporté.")

if __name__ == "__main__":
    main()
