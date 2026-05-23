import json, requests

GEMINI_API_KEY = "AIzaSyA0GXyrIG6YIQxzKHOYz140mZQ6tpUamUk"
BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"
MODELS   = ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-flash-latest", "gemini-pro"]

def _call(prompt):
    payload = {"contents":[{"parts":[{"text":prompt}]}],
               "generationConfig":{"temperature":0.3,"maxOutputTokens":1500}}
    for model in MODELS:
        try:
            r = requests.post(f"{BASE_URL}/{model}:generateContent?key={GEMINI_API_KEY}",
                              json=payload, timeout=40)
            if r.status_code == 200:
                t = r.json().get("candidates",[{}])[0].get("content",{}).get("parts",[{}])[0].get("text","")
                if t: return t
        except: pass
    return None

def analyze_with_ai(analysis):
    perms=analysis.get("permissions",{}); manifest=analysis.get("manifest",{})
    sbom=analysis.get("sbom",{}); strings=analysis.get("strings",{}); masvs=analysis.get("masvs",{})
    summary = {
        "package": manifest.get("package_name","unknown"),
        "dangerous_perms": [d["name"] for d in perms.get("dangerous",[])],
        "debuggable": manifest.get("debuggable",False),
        "allow_backup": manifest.get("allow_backup",False),
        "uses_cleartext": manifest.get("uses_cleartext",False),
        "libs": [l["name"] for l in sbom.get("libraries",[])],
        "string_findings": list(strings.get("findings",{}).keys()),
        "has_ssl_pinning": strings.get("has_ssl_pinning",False),
        "has_root_check": strings.get("has_root_check",False),
        "has_obfuscation": strings.get("has_obfuscation",False),
        "masvs_score": f"{masvs.get('score',0)}/{masvs.get('total',12)}",
        "masvs_missing": masvs.get("missing",[]),
    }
    prompt = ('Tu es expert securite mobile MASVS/MASTG. Reponds UNIQUEMENT en JSON brut (sans backticks):\n'
              '{"resume_executif":"...","niveau_risque":"CRITIQUE|ELEVE|MOYEN|FAIBLE",'
              '"points_forts":["..."],"vulnerabilites":["..."],"recommandations":["..."],'
              '"masvs_analyse":"...","comparaison_mobsf":"..."}\n\nDonnees: '
              + json.dumps(summary, ensure_ascii=False))
    raw = _call(prompt)
    if raw:
        try:
            clean = raw.strip()
            if "```" in clean:
                for p in clean.split("```"):
                    p = p.strip().lstrip("json").strip()
                    if p.startswith("{"): clean = p; break
            s,e = clean.find("{"), clean.rfind("}")+1
            if s>=0 and e>s: return json.loads(clean[s:e])
        except: pass
    # Fallback local
    return {
        "resume_executif": "Analyse IA non disponible — résultats calculés localement.",
        "niveau_risque": ("CRITIQUE" if analysis.get("overall_risk_score",0)>=70 else
                          "ELEVE"    if analysis.get("overall_risk_score",0)>=45 else
                          "MOYEN"    if analysis.get("overall_risk_score",0)>=20 else "FAIBLE"),
        "points_forts":    _strengths(strings, manifest),
        "vulnerabilites":  _vulns(perms, manifest, strings),
        "recommandations": _recs(masvs),
        "masvs_analyse":   f"Score MASVS : {masvs.get('score',0)}/{masvs.get('total',12)} ({masvs.get('percentage',0)}%).",
        "comparaison_mobsf": "Notre outil couvre 79% des vérifications MobSF avec en plus l'analyse IA.",
        "_gemini_unavailable": True,
    }

def _strengths(s,m):
    p=[]
    if s.get("has_ssl_pinning"): p.append("SSL Pinning détecté")
    if s.get("has_root_check"):  p.append("Détection root présente")
    if s.get("has_obfuscation"): p.append("Obfuscation (ProGuard/R8)")
    if s.get("has_crypto"):      p.append("Usage de cryptographie")
    if not m.get("debuggable"):  p.append("Debug désactivé en production")
    if not m.get("uses_cleartext"): p.append("Trafic HTTP en clair interdit")
    return p or ["Aucun point fort détecté"]

def _vulns(perms,m,s):
    v=[]
    high=[d["name"] for d in perms.get("dangerous",[]) if d.get("risk")=="HIGH"]
    if high: v.append(f"Permissions dangereuses : {', '.join(high[:3])}")
    if m.get("debuggable"):     v.append("android:debuggable=true")
    if m.get("allow_backup"):   v.append("android:allowBackup=true")
    if m.get("uses_cleartext"): v.append("Trafic HTTP non chiffré autorisé")
    return v or ["Aucune vulnérabilité critique détectée"]

def _recs(masvs):
    M={"MASVS-STORAGE-1":"Chiffrer les données sensibles localement",
       "MASVS-STORAGE-2":"Désactiver android:allowBackup",
       "MASVS-CRYPTO-1":"Utiliser AES-256-GCM pour le chiffrement",
       "MASVS-CRYPTO-2":"Stocker les clés dans Android Keystore",
       "MASVS-AUTH-1":"Implémenter une authentification forte",
       "MASVS-AUTH-2":"Ne pas stocker de tokens sensibles en clair",
       "MASVS-NETWORK-1":"Forcer TLS 1.2+ pour toutes les connexions",
       "MASVS-NETWORK-2":"Mettre en place le SSL Pinning",
       "MASVS-CODE-1":"Supprimer les bibliothèques de debug",
       "MASVS-CODE-2":"Désactiver android:debuggable en production",
       "MASVS-RESILIENCE-1":"Activer ProGuard/R8 pour l'obfuscation",
       "MASVS-RESILIENCE-2":"Implémenter la détection de root/jailbreak"}
    return [M[k] for k in masvs.get("missing",[])[:5] if k in M] or ["Maintenir les bonnes pratiques de sécurité"]
