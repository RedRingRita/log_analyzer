from colorama import Fore

# Chaque règle est un dict avec :
# - "event_id": fonction qui prend la ligne et retourne True/False
# - "label": texte à afficher (avec couleur)
# - "color": couleur colorama (pour le label)
# - "show_line": bool, si on ajoute la ligne complète après le label

rules = [
    {
        "event_id": "4625",
        "label": "[ECHEC CONNEXION WINDOWS]",
        "color": Fore.RED,
        "show_line": True,
    },
    {
        "event_id": "4624",
        "label": "[CONNEXION WINDOWS REUSSIE]",
        "color": Fore.GREEN,
        "show_line": True,
    },
    {
        "event_id": "4672",
        "label": "[CONNEXION AVEC PRIVILEGES ELEVES]",
        "color": Fore.YELLOW,
        "show_line": True,
    },
        {
        "event_id":"4720",
        "label": "[CREATION DE NOUVEL UTILISATEUR]",
        "color": Fore.CYAN,
        "show_line": True,
    },
    {
        "event_id":"4726",
        "label": "[SUPPRESSION D’UN UTILISATEUR]",
        "color": Fore.MAGENTA,
        "show_line": True,
    },
]
