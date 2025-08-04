from colorama import Fore

# Chaque règle est un dict avec :
# - "match": fonction qui prend la ligne et retourne True/False
# - "label": texte à afficher (avec couleur)
# - "color": couleur colorama (pour le label)
# - "show_line": bool, si on ajoute la ligne complète après le label

rules = [
    {
        "match": lambda line: "Failed password" in line,
        "label": "[ECHEC CONNEXION SSH]",
        "color": Fore.RED,
        "show_line": True,
    },
    {
        "match": lambda line: "Accepted password" in line,
        "label": "[CONNEXION SSH REUSSIE]",
        "color": Fore.GREEN,
        "show_line": True,
    },
    {
        "match": lambda line: "sudo:" in line or "COMMAND=" in line,
        "label": "[UTILISATION DE SUDO / PRIVILEGE]",
        "color": Fore.YELLOW,
        "show_line": True,
    },
]
