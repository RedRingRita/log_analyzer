"""
log_analyzer_auto.py
Analyse automatique de logs Linux (texte) et Windows (EVTX) sans spécifier l'OS.
Usage : python log_analyzer_auto.py --file /var/log/auth.log
      python log_analyzer_auto.py --file Security.evtx
"""

import argparse
import os
import sys

try:
    from Evtx.Evtx import Evtx
except ImportError:
    Evtx = None
    print("⚠️ Module python-evtx non trouvé. Installe-le avec 'pip install python-evtx' pour analyser les logs Windows EVTX.")

def analyze_linux_log(filepath):
    """
    Analyse simple d'un fichier log Linux (texte).
    Recherche des échecs/succès de connexion SSH et usage de sudo.
    """
    if not os.path.isfile(filepath):
        print(f"Erreur : le fichier {filepath} n'existe pas.")
        return
    
    print(f"\n--- Analyse du fichier Linux : {filepath} ---")
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if "Failed password" in line:
                print("[ECHEC CONNEXION] " + line.strip())
            elif "Accepted password" in line:
                print("[CONNEXION REUSSIE] " + line.strip())
            elif "sudo:" in line:
                print("[COMMANDE SUDO] " + line.strip())

def analyze_windows_log(filepath):
    """
    Analyse d'un fichier EVTX Windows.
    Recherche d'évènements d'échec de connexion.
    """
    if Evtx is None:
        print("Erreur : impossible d'analyser les logs Windows sans le module python-evtx.")
        return
    
    if not os.path.isfile(filepath):
        print(f"Erreur : le fichier {filepath} n'existe pas.")
        return
    
    print(f"\n--- Analyse du fichier Windows EVTX : {filepath} ---")

    try:
        with Evtx(filepath) as log:
            for record in log.records():
                xml_str = record.xml()
                if "An account failed to log on" in xml_str:
                    print("[ECHEC CONNEXION WINDOWS]")
                    print(xml_str)
                    print("-" * 40)
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier EVTX : {e}")

def detect_log_type(filepath):
    """
    Détecte automatiquement le type de log en fonction de l'extension et du contenu.
    """
    if not os.path.isfile(filepath):
        print(f"Erreur : le fichier {filepath} n'existe pas.")
        return None
    
    ext = os.path.splitext(filepath)[1].lower()
    
    if ext == ".evtx":
        return "windows"
    else:
        # Tentative de vérifier si le fichier est texte ou binaire (simplifié)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                f.read(1024)  # lire un petit bout pour voir si c'est lisible en texte
            return "linux"
        except UnicodeDecodeError:
            # fichier non texte, on ne sait pas
            return None


# Interface CLI
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
        print("Impossible de détecter le type de log ou format non supporté.")

if __name__ == "__main__":
    main()
