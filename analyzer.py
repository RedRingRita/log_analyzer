import re
import os
import json
import argparse
from datetime import datetime
from collections import defaultdict

# --- Détections des événements suspects ---
def parse_log_line(line):
    patterns = {
        "ssh_bruteforce": r"Failed password for (?:invalid user )?(\w+) from ([\d.]+)",
        "root_login": r"Accepted password for root from ([\d.]+)",
        "invalid_user": r"Invalid user (\w+) from ([\d.]+)",
        "sudo_usage": r"sudo:.*?: TTY=.*? ; PWD=.*? ; USER=.*? ; COMMAND=.*"
    }

    results = {}

    for key, pattern in patterns.items():
        match = re.search(pattern, line)
        if match:
            results[key] = match.groups()

    return results


# --- Analyse complète du fichier ---
def analyze_log(file_path):
    findings = {
        "ssh_bruteforce": defaultdict(int),
        "root_logins": [],
        "invalid_users": [],
        "sudo_commands": 0,
        "total_lines": 0
    }

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            findings["total_lines"] += 1
            results = parse_log_line(line)

            if "ssh_bruteforce" in results:
                ip = results["ssh_bruteforce"][1]
                findings["ssh_bruteforce"][ip] += 1

            if "root_login" in results:
                ip = results["root_login"][0]
                findings["root_logins"].append(ip)

            if "invalid_user" in results:
                user, ip = results["invalid_user"]
                findings["invalid_users"].append({"user": user, "ip": ip})

            if "sudo_usage" in results:
                findings["sudo_commands"] += 1

    # Convert defaultdict to dict for JSON serialization
    findings["ssh_bruteforce"] = dict(findings["ssh_bruteforce"])
    return findings


# --- Génération du rapport ---
def save_report(findings, output_dir="report"):
    os.makedirs(output_dir, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    output_file = os.path.join(output_dir, f"{date_str}_report.json")

    with open(output_file, "w") as f:
        json.dump(findings, f, indent=4)

    print(f"[+] Rapport sauvegardé dans : {output_file}")


# --- Interface CLI ---
def main():
    parser = argparse.ArgumentParser(description="Analyseur de logs auth.log pour détection d'événements suspects")
    parser.add_argument("logfile", help="Chemin vers le fichier auth.log à analyser")

    args = parser.parse_args()

    if not os.path.exists(args.logfile):
        print(f"[!] Fichier non trouvé : {args.logfile}")
        return

    print("[*] Analyse en cours...")
    findings = analyze_log(args.logfile)
    save_report(findings)


if __name__ == "__main__":
    main()
