<<<<<<< HEAD
# Evidence Collector & Compliance Pack — Application Web
## ENSA Marrakech · Audit de sécurité mobile MASVS/MASTG
=======
# Evidence Collector & Compliance Pack

**A Web-Based Platform for Automated Android APK Security Auditing and AI-Assisted MASVS/MASTG Reporting**

> ENSA Marrakech · Génie Cyber Défense · Audit de sécurité mobile MASVS/MASTG  
> Lachgar Mohamed (UCA / L2IS), Ezbiri Amira, SAS Houda, Bachir Soukaina, El Yamani Oumayma
>>>>>>> 692c93e3e7c6b3fd6054174cce46a895793dc7af

---

## Description

<<<<<<< HEAD
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
=======
Evidence Collector & Compliance Pack is an **open-source, browser-accessible web platform** that automates the static analysis of Android APK files and generates auditor-ready evidence packages.

**Input** : Fichier APK Android (≤ 100 MB)  
**Output** : Rapport HTML auto-contenu + export JSON brut

The platform orchestrates **eight independent analysis modules** in a single Python/Flask backend, renders results in a single-page web interface (SPA), and uses **Google Gemini Flash** to synthesize pre-computed findings into plain-language executive summaries.

> **⚠️ Important precision on AI usage**: Compliance verdicts for each MASVS requirement are determined entirely by **rule-based static checks** on manifest flags, permission lists, SBOM entries, and DEX string patterns. Gemini Flash is used exclusively to *summarize* these pre-computed verdicts into an executive narrative and prioritized remediation recommendations. This tool provides **AI-assisted reporting**, not AI-driven compliance inference.

---
## Demonstration

https://youtu.be/w3HuxrMwQ2c

---
## Fonctionnalités

### 1. Hash Computation (`apk_hasher`)
- Calcul des empreintes **SHA-256** et **MD5** en mode streaming (hashlib)
- Taille en octets, Ko et Mo
- SHA-256 est l'identifiant de reproductibilité primaire (MASVS-RESILIENCE-1, Chap. 14)

### 2. Extraction du Manifest (`manifest_parser`)
- Parsing du fichier **AndroidManifest.xml** (format binaire AXML) via `pyaxmlparser`
- Extraction : nom du package, version, SDK Min/Target, nombre de composants
- Extraction des quatre flags de sécurité critiques :
  - `android:debuggable`
  - `android:allowBackup`
  - `usesCleartextTraffic`
  - `networkSecurityConfig`
- Fallback léger en cas d'indisponibilité de pyaxmlparser
- Limitations connues : APKs splitté, APK packés, binary XML malformé

### 3. Analyse des permissions (`permission_analyzer`)
- Classification en trois niveaux : **HIGH / MEDIUM / NORMAL / UNKNOWN**
- Dictionnaire de **25 permissions dangereuses** annotées avec niveau de risque, exigence MASVS et chapitre
- Score de risque composite :

  ```
  s = min(100, 15 × n_HIGH + 7 × n_MEDIUM)
  ```

  Les coefficients 15 et 7 reflètent la pondération de sévérité MASVS v2.0 (2023) : les permissions HIGH donnent un accès direct à des données personnelles sensibles ou à des ressources système ; les permissions MEDIUM exposent à des risques de confidentialité indirects.

### 4. Génération de SBOM (`sbom_generator`)
- Correspondance des entrées ZIP de l'APK avec un dictionnaire d'empreintes de **36 bibliothèques Java/Kotlin connues**
- Identification des bibliothèques natives (`lib/**/*.so`)
- Annotation : nom canonique, vendeur, catégorie fonctionnelle (Network, Crypto, DI, Debug, etc.)
- Marquage des bibliothèques inappropriées en production (Stetho, LeakCanary, Mockito)
- **Note** : il s'agit d'une identification par empreinte, non d'un SBOM standard CycloneDX/SPDX

### 5. Analyse de chaînes DEX (`strings_analyzer`)
- Extraction de toutes les chaînes ASCII imprimables ≥ 6 caractères (≤ 4 Mo par fichier DEX)
- 9 expressions régulières pour la détection de secrets :
  - URLs HTTP/HTTPS, adresses email, adresses IPv4
  - Clés API génériques, AWS Access Key IDs, tokens JWT
  - En-têtes de clés privées PEM, Google API Keys, Firebase RTDB URLs
- **Anonymisation** : les secrets détectés sont tronqués aux 8 premiers caractères suivis de `***` avant export HTML/JSON

### 6. Indicateurs comportementaux (`strings_analyzer` — indicateurs booléens)
- 8 vérifications booléennes par analyse statique des chaînes DEX (non par observation runtime) :
  - Obfuscation (ProGuard / R8)
  - SSL Pinning
  - Détection root / jailbreak
  - Anti-débogage
  - Détection d'émulateur
  - Chargement dynamique de code
  - Usage de cryptographie (AES, RSA, MessageDigest, Cipher)
  - Réflexion Java

> **Note terminologique** : ces indicateurs sont qualifiés de "comportementaux" mais sont dérivés de patterns de chaînes DEX statiques, **non** d'observations dynamiques à l'exécution.

### 7. Conformité MASVS / MASTG (`masvs_mapper`)
- **12 exigences** vérifiées (MASVS v2.0, 2023) sur **6 chapitres** :

| Exigence             | Catégorie  | Chap. | Source de preuve                          |
|----------------------|------------|-------|-------------------------------------------|
| MASVS-STORAGE-1      | Stockage   | 4     | Permissions de stockage dangereuses       |
| MASVS-STORAGE-2      | Stockage   | 4     | Flag allowBackup                          |
| MASVS-CRYPTO-1       | Crypto     | 6     | Indicateur crypto dans chaînes DEX        |
| MASVS-CRYPTO-2       | Crypto     | 6     | Absence de clés API en clair              |
| MASVS-AUTH-1         | Auth       | 7     | Absence de tokens JWT en clair            |
| MASVS-AUTH-2         | Auth       | 7     | Flag debuggable                           |
| MASVS-NETWORK-1      | Réseau     | 9     | Flag usesCleartextTraffic                 |
| MASVS-NETWORK-2      | Réseau     | 9     | SSL Pinning / NetworkSecurityConfig       |
| MASVS-CODE-1         | Code       | 10    | Absence de libs debug/test dans SBOM      |
| MASVS-CODE-2         | Code       | 10    | Flag debuggable + vérification SBOM       |
| MASVS-RESILIENCE-1   | Résilience | 14    | Obfuscation dans chaînes DEX              |
| MASVS-RESILIENCE-2   | Résilience | 14    | Détection root dans chaînes DEX           |

- Chaque vérification retourne un booléen pass/fail et une chaîne détails traçable à sa source de preuve

### 8. Analyse IA — Résumé Exécutif (`gemini_client`)
- Envoi d'un prompt structuré à **Google Gemini Flash** (`gemini-1.5-flash`)
- Validation de la réponse JSON contre un schéma strict à 6 clés :
  `resume_executif`, `niveau_risque`, `points_forts`, `vulnerabilites`, `recommandations`, `masvs_analyse`
- **Fallback déterministe local** : si l'API est indisponible (ex. HTTP 429), un algorithme local fournit un résumé exécutif calculé localement — l'onglet IA n'est **jamais** vide

### 9. Génération de Rapport (`report_generator`)
- Rapport **HTML** auto-contenu (offline-usable, audit-ready), incluant une section Limitations & Disclaimer
- Export **JSON brut** pour post-traitement programmatique ou intégration avec des systèmes de ticketing
- Rapports adressables par UUID de tâche sous `reports/`

---

## Comparaison avec MobSF

Evidence Collector couvre **79% des vérifications d'analyse statique de MobSF** (11 sur 14 catégories) tout en offrant une fonctionnalité exclusive : le résumé exécutif par LLM.

| Fonctionnalité                          | EC v1.0.0 | MobSF v4.5 | ApkTool | QARK |
|-----------------------------------------|:---------:|:----------:|:-------:|:----:|
| Hash APK (SHA-256 / MD5)                | ✓         | ✓          | ×       | △    |
| Extraction du manifest                  | ✓         | ✓          | ✓       | ✓    |
| Classification des permissions          | ✓         | ✓          | ×       | ✓    |
| Mapping MASVS par permission            | ✓         | △          | ×       | ×    |
| SBOM par empreinte (Java + natif)       | ✓         | △          | ×       | ×    |
| Détection de secrets / chaînes DEX      | ✓         | ✓          | ×       | ✓    |
| Indicateurs comportementaux (DEX)       | ✓         | ✓          | ×       | ×    |
| Score de conformité MASVS / MASTG       | ✓         | ✓          | ×       | △    |
| Résumé exécutif IA (LLM — Gemini Flash) | ✓         | ×          | ×       | ×    |
| Export HTML + JSON                      | ✓         | ✓          | ×       | ✓    |
| Interface web                           | ✓         | ✓*         | ×       | ×    |
| Déploiement local sans configuration    | ✓         | △          | ×       | ×    |
| Analyse de la chaîne de certificats     | ×         | ✓          | ×       | △    |
| Décompilation source (JADX/Smali)       | ×         | ✓          | ✓       | ×    |
| Interception trafic runtime             | ×         | ✓          | ×       | ×    |
| Hooks Frida / Xposed                    | ×         | ✓          | ×       | ×    |
| Couverture statique vs MobSF            | **79%**   | —          | —       | —    |

> ✓ = supporté ; △ = partiel ; × = non supporté  
> *MobSF fournit une interface web mais nécessite Docker ou un serveur dédié.

---

## Évaluation — Dataset APK

La plateforme a été évaluée sur 4 APKs Android couvrant différents profils de risque, analysés le 22 mai 2026 avec Evidence Collector v1.0.0 et MobSF v4.5.0 (Windows 11, Python 3.13, Android Emulator API 29 AOSP) :

| APK            | Package                   | Ver.   | Taille   | SHA-256 (16 premiers hex) | SDK Min | Risque EC | Score MASVS |
|----------------|---------------------------|--------|----------|---------------------------|---------|-----------|-------------|
| FireStorm      | com.pwnsec.firestorm      | 1.0    | 4.26 MB  | `7f9e512109127afd`        | 28      | Moyen     | 10/12 (83%) |
| FireInTheHole  | com.PwnSec.fireinthehole  | 1.0    | 5.68 MB  | `7ef29fe545103a38`        | 24      | Élevé     | 8/12        |
| F-Droid        | org.fdroid.fdroid         | 1.23.2 | 11.85 MB | `985f5181d48bb6ba`        | 23      | Critique  | 8/12        |
| ezmobile       | com.pwnsec.ezmobile       | 1.0    | 4.56 MB  | `d8a612c4c4d9efa0`        | 24      | Faible    | 11/12       |

---

## Qualité du Code

Évaluation SonarQube (Community Edition 10.4, profil qualité par défaut, scan du 22 mai 2026) :

| Métrique              | Backend (Python/Flask) | Frontend (HTML/JS) |
|-----------------------|:----------------------:|:------------------:|
| Quality Gate Status   | ✓ Passed               | ✓ Passed           |
| Reliability Rating    | A                      | B                  |
| Security Rating       | A                      | A                  |
| Maintainability       | A                      | B                  |
| Code Duplication      | < 2%                   | < 4%               |
| Security Hotspots     | 0                      | 0                  |

L'intégration continue est configurée via **GitHub Actions** : le pipeline exécute `pytest` (couverture ≥ 78%) et `flake8` sur chaque push vers `main`.
>>>>>>> 692c93e3e7c6b3fd6054174cce46a895793dc7af

---

## Installation

```bash
<<<<<<< HEAD
# 1. Créer un environnement virtuel
=======
# 1. Cloner le dépôt
git clone https://github.com/Huuudaa/Evidence_Collector.git
cd Evidence_Collector

# 2. Créer un environnement virtuel
>>>>>>> 692c93e3e7c6b3fd6054174cce46a895793dc7af
python -m venv venv
source venv/bin/activate      # Linux / macOS
venv\Scripts\activate         # Windows

<<<<<<< HEAD
# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Lancer le serveur
python app.py
```

## Accès

Ouvrir le navigateur à : **http://localhost:5000**
=======
# 3. Installer les dépendances (versions épinglées)
pip install -r requirements.txt

# 4. (Optionnel) Configurer la clé API Gemini
# Exporter la variable d'environnement GEMINI_API_KEY
# sans clé, le fallback local s'active automatiquement

# 5. Lancer le serveur
python app.py
```

**Via Docker (recommandé pour un déploiement reproductible) :**

```bash
docker compose up --build
# Ouvrir http://localhost:5000
```

**Accès :** ouvrir le navigateur à `http://localhost:5000`

> **Note** : l'application nécessite un serveur Python/Flask local. Elle n'est pas "sans installation" au sens strict, mais ne nécessite pas de configuration avancée ni de serveur dédié.

---

## Métadonnées du code

| Réf. | Description                        | Valeur                                                                                   |
|------|------------------------------------|------------------------------------------------------------------------------------------|
| C1   | Version actuelle                   | v1.0.0                                                                                   |
| C2   | Lien permanent (dépôt + release)   | https://github.com/Huuudaa/Evidence_Collector/releases/tag/v1.0.0                       |
| C3   | Capsule reproductible              | `docker-compose.yml` à la racine du dépôt ; DOI Zenodo à assigner après publication     |
| C4   | Licence                            | MIT                                                                                      |
| C5   | Système de versionnement           | Git                                                                                      |
| C6   | Langages & services                | Python 3.10, Flask 3.0.3, HTML5/CSS3, JavaScript (ES2020), pyaxmlparser 0.3.24, Gemini Flash (`gemini-1.5-flash`) |
| C7   | Dépendances (versions épinglées)   | Python ≥ 3.8 ; Flask == 3.0.3 ; pyaxmlparser == 0.3.24 ; requests == 2.31.0 ; voir `requirements.txt` |
| C8   | Documentation développeur          | https://github.com/Huuudaa/Evidence_Collector/blob/main/README.md                       |
| C9   | Contact support                    | m.lachgar@uca.ac.ma                                                                      |
>>>>>>> 692c93e3e7c6b3fd6054174cce46a895793dc7af

---

## Structure du projet

```
<<<<<<< HEAD
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
=======
Evidence_Collector/
├── app.py                      # Serveur Flask — endpoint REST POST /api/analyze
├── requirements.txt            # Dépendances Python avec versions épinglées
├── docker-compose.yml          # Déploiement Docker reproductible
├── schema/
│   └── report_schema.json      # Schéma JSON des rapports exportés
├── modules/
│   ├── apk_analyzer.py         # Orchestrateur — délègue aux 8 modules
│   ├── apk_hasher.py           # Hash SHA-256 / MD5 (streaming)
│   ├── manifest_parser.py      # Extraction AndroidManifest.xml (AXML)
│   ├── permission_analyzer.py  # Classification des permissions + score de risque
│   ├── sbom_generator.py       # SBOM — identification par empreinte (36 libs)
│   ├── strings_analyzer.py     # Extraction chaînes DEX + indicateurs comportementaux
│   ├── masvs_mapper.py         # Conformité MASVS (12 exigences) + comparaison MobSF
│   └── gemini_client.py        # Résumé IA Gemini Flash + fallback local
├── templates/
│   └── index.html              # Interface web SPA (Jinja2 + Vanilla JS)
├── uploads/                    # APKs temporaires (supprimés immédiatement après analyse)
└── reports/                    # Rapports persistants adressables par UUID (HTML + JSON)
>>>>>>> 692c93e3e7c6b3fd6054174cce46a895793dc7af
```

---

<<<<<<< HEAD
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
=======
## API REST

| Endpoint              | Méthode | Description                                           |
|-----------------------|---------|-------------------------------------------------------|
| `/api/analyze`        | POST    | Upload + analyse APK (max 100 MB, MIME validé)        |
| `/report/<id>`        | GET     | Télécharger le rapport HTML par UUID                  |
| `/report-json/<id>`   | GET     | Télécharger l'export JSON brut par UUID               |

**Codes HTTP** : `200` succès · `400` fichier invalide · `500` erreur interne
>>>>>>> 692c93e3e7c6b3fd6054174cce46a895793dc7af

---

## Chapitres MASVS couverts

- **Chapitre 4** : Stockage des données
- **Chapitre 6** : Cryptographie
- **Chapitre 7** : Authentification
- **Chapitre 9** : Communications réseau
<<<<<<< HEAD
- **Chapitre 10** : Code et qualité
- **Chapitre 14** : Résistance au reverse engineering
=======
- **Chapitre 10** : Qualité du code
- **Chapitre 14** : Résistance au reverse engineering

---

## Limitations connues

- Le SBOM est basé sur la correspondance d'empreintes de 36 bibliothèques connues ; les bibliothèques non référencées ne sont pas détectées. Il n'est pas conforme CycloneDX/SPDX.
- L'analyse des chaînes DEX est limitée à **4 Mo par fichier DEX** ; les très grandes apps peuvent avoir des chaînes non analysées.
- Les indicateurs comportementaux sont des **indicateurs statiques** (patterns dans les chaînes DEX), pas des observations dynamiques à l'exécution.
- La détection de secrets peut produire des **faux positifs** (ex. chaînes ressemblant à des clés dans des ressources compressées).
- La correspondance par mots-clés pour les indicateurs comportementaux peut être mise en échec par une **obfuscation agressive**.
- Aucun mécanisme d'authentification n'est implémenté en v1.0.0 ; les rapports générés sont accessibles à tout utilisateur du réseau local.
- Les appels Gemini Flash s'exécutent côté client (JavaScript) ; la clé API doit être gérée avec précaution.

---
>>>>>>> 692c93e3e7c6b3fd6054174cce46a895793dc7af
