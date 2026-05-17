# Evidence Collector & Compliance Pack — Application Web
## ENSA Marrakech · Audit de sécurité mobile MASVS/MASTG

---

## Description

Application web Flask pour l'audit statique et dynamique d'APK Android.

**Input** : Fichier APK  
**Output** : Rapport HTML complet + JSON

---

## Fonctionnalités

### Audit statique
- Hash SHA-256 / MD5 de l'APK
- Extraction et analyse du AndroidManifest.xml
- Classification des permissions (dangereuses / normales) avec mapping MASVS
- SBOM (Software Bill of Materials) — détection de 35+ bibliothèques
- Extraction de chaînes sensibles (URLs, emails, clés API, JWT, clés AWS)

### Indicateurs dynamiques (analyse statique du comportement)
- Détection d'obfuscation (ProGuard / R8)
- Présence de SSL Pinning
- Détection root / jailbreak
- Anti-débogage
- Détection d'émulateur
- Chargement dynamique de code
- Usage de cryptographie
- Réflexion Java

### Conformité MASVS / MASTG
- 12 exigences vérifiées (Chapitres 4, 6, 7, 9, 10, 14)
- Score en pourcentage
- Détails par exigence

### Analyse IA
- Résumé exécutif par Gemini Flash
- Niveau de risque global
- Points forts / vulnérabilités / recommandations
- Comparaison avec MobSF

### Rapport
- Rapport HTML téléchargeable
- Export JSON brut
- Comparaison détaillée avec MobSF

---

## Installation

```bash
# 1. Créer un environnement virtuel
python -m venv venv
source venv/bin/activate      # Linux / macOS
venv\Scripts\activate         # Windows

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Lancer le serveur
python app.py
```

## Accès

Ouvrir le navigateur à : **http://localhost:5000**

---

## Structure du projet

```
evidence_collector_web/
├── app.py                    # Serveur Flask principal
├── requirements.txt
├── modules/
│   ├── apk_analyzer.py       # Orchestrateur d'analyse
│   ├── apk_hasher.py         # Hash SHA-256 / MD5
│   ├── manifest_parser.py    # Extraction AndroidManifest
│   ├── permission_analyzer.py# Classification des permissions
│   ├── sbom_generator.py     # SBOM — 35+ bibliothèques
│   ├── strings_analyzer.py   # Extraction de chaînes sensibles
│   ├── masvs_mapper.py       # Conformité MASVS + comparaison MobSF
│   └── gemini_client.py      # Analyse IA Gemini Flash
├── templates/
│   └── index.html            # Interface web SPA pastel
├── uploads/                  # Fichiers APK temporaires (auto-nettoyés)
└── reports/                  # Rapports générés (HTML + JSON)
```

---

## Comparaison avec MobSF

| Fonctionnalité              | MobSF | Evidence Collector |
|-----------------------------|-------|--------------------|
| Analyse de manifest         | Oui   | Oui                |
| Hash & signature            | Oui   | Oui                |
| Permissions                 | Oui   | Oui                |
| SBOM                        | Oui   | Oui                |
| Secrets hardcodés           | Oui   | Oui                |
| MASVS/MASTG                 | Oui   | Oui                |
| Analyse IA (LLM)            | Non   | **Oui (Gemini)**   |
| Trafic réseau en direct     | Oui   | Non                |
| Hook Frida/Xposed           | Oui   | Non                |

---

## Chapitres MASVS couverts

- **Chapitre 4** : Stockage des données
- **Chapitre 6** : Cryptographie
- **Chapitre 7** : Authentification
- **Chapitre 9** : Communications réseau
- **Chapitre 10** : Code et qualité
- **Chapitre 14** : Résistance au reverse engineering
