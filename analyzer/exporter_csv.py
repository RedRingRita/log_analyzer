import csv
from datetime import datetime
import os

def exporter_resultats_csv(resultats: list, origin: str, chemin: str = "../reports/resultats.csv"):
    """
    Exporte les résultats dans un fichier CSV.

    Args:
        resultats (list): Liste de dictionnaires contenant les résultats à exporter.
        origin (str): Origine des logs (ex: "linux", "windows").
        chemin (str): Chemin du fichier de sortie.
    """
    try:
        # Création du dossier si besoin
        dossier = os.path.dirname(chemin)
        if dossier and not os.path.exists(dossier):
            os.makedirs(dossier)

        # Ajout de la date et de l'origine dans le nom du fichier si déjà existant
        if os.path.exists(chemin):
            base, ext = os.path.splitext(chemin)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            chemin = f"{base}_{origin}_{timestamp}{ext}"

        # Ouverture du fichier en écriture
        with open(chemin, 'w', newline='', encoding='utf-8') as f:
            if not resultats:
                raise ValueError("La liste des résultats est vide.")

            # Utilisation des clés du premier élément comme en-têtes
            fieldnames = resultats[0].keys()
            writer = csv.DictWriter(f, fieldnames=fieldnames)

            writer.writeheader()
            writer.writerows(resultats)

        print(f"✅ Résultats CSV exportés avec succès dans : {chemin}")

    except Exception as e:
        print(f"❌ Erreur lors de l’export CSV : {e}")
