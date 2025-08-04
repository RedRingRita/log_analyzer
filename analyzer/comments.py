from colorama import init, Fore, Style

# Initialise colorama pour que les couleurs fonctionnent sous Windows
init(autoreset=True)

def comment_info(message):
    print(f"{Fore.CYAN}[INFO] {message}{Style.RESET_ALL} ")

def comment_warning(message):
    print(f"{Fore.YELLOW}[WARNING] {message}{Style.RESET_ALL}")

def comment_error(message):
    print(f"{Fore.RED}{Style.BRIGHT}[ERROR] {message}")

def comment_success(message):
    print(f"{Fore.GREEN}[SUCCESS] {message}{Style.RESET_ALL}")

def comment_debug(message):
    print(f"{Fore.MAGENTA}[DEBUG] {message}{Style.RESET_ALL}")

    # ─── Colorama styles disponibles ─────────────────────────────────────────────
# 
# Couleurs de texte (Fore) :
#   - Fore.BLACK
#   - Fore.RED
#   - Fore.GREEN
#   - Fore.YELLOW
#   - Fore.BLUE
#   - Fore.MAGENTA
#   - Fore.CYAN
#   - Fore.WHITE
#   - Fore.LIGHTBLACK_EX
#   - Fore.LIGHTRED_EX
#   - Fore.LIGHTGREEN_EX
#   - Fore.LIGHTYELLOW_EX
#   - Fore.LIGHTBLUE_EX
#   - Fore.LIGHTMAGENTA_EX
#   - Fore.LIGHTCYAN_EX
#   - Fore.LIGHTWHITE_EX
#
# Couleurs de fond (Back) :
#   - Back.RED, Back.GREEN, etc. (mêmes noms que Fore)
#
# Styles de texte :
#   - Style.DIM       → texte atténué
#   - Style.NORMAL    → texte normal
#   - Style.BRIGHT    → texte plus lumineux
#   - Style.RESET_ALL → réinitialise couleurs & styles
# 
# Exemple d'utilisation :
# print(f"{Fore.RED}{Style.BRIGHT}[ERROR] {message}")
# ─────────────────────────────────────────────────────────────────────────────