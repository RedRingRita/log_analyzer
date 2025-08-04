# 🧙‍♀️ Witchy Log Analyzer

**Witchy Analyzer** est un outil léger en Python conçu pour analyser des fichiers journaux (logs) ou des fichiers EVTX à la recherche de comportements suspects. Il s'appuie sur un ensemble de règles personnalisables afin de détecter des motifs spécifiques dans les logs Linux ou Windows.

## ✨ Fonctionnalités

- 🔍 Analyse de fichiers logs Linux (texte brut) ou journaux Windows (EVTX)
- 📜 Détection basée sur des règles simples (regex) pour repérer des comportements suspects
- 🧠 Séparation claire des règles pour Linux et Windows
- 📤 Export des résultats en **JSON** ou **CSV**
- 📁 Organisation modulaire du code pour faciliter l'ajout de nouvelles règles ou formats de sortie

---

## ⚙️ Installation

```bash
git clone https://github.com/RedRingRita/log_analyzer.git
cd log_analyzer/analyzer
python -m venv venv
source venv/bin/activate  # ou venv\Scripts\activate sous Windows
pip install -r requirements.txt
