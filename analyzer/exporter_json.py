import json
from datetime import datetime
import os

def exporter_resultats_json(resultats: list, origin: str, chemin: str = "../reports/resultats.json"):
    """
    Exporte les résultats dans un fichier JSON.

    Args:
        resultats (list): Liste de dictionnaires contenant les résultats à exporter.
        chemin (str): Chemin du fichier de sortie.
    """
    try:
        # Création du dossier si besoin
        dossier = os.path.dirname(chemin)
        if dossier and not os.path.exists(dossier):
            os.makedirs(dossier)

        # Ajout de la date dans le nom du fichier si déjà existant
        if os.path.exists(chemin):
            base, ext = os.path.splitext(chemin)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            chemin = f"{base}_{origin}_{timestamp}{ext}"

        with open(chemin, 'w', encoding='utf-8') as f:
            json.dump(resultats, f, ensure_ascii=False, indent=4)
        print(f"✅ Résultats exportés avec succès dans : {chemin}")

    except Exception as e:
        print(f"❌ Erreur lors de l’export : {e}")
