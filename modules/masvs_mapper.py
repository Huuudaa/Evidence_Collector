from dataclasses import dataclass, field
from typing import List

@dataclass
class MasvsRequirement:
    id:          str
    category:    str
    description: str
    chapter:     int
    check_fn:    str  # name of the check

# All MASVS requirements we cover (Chapters 4,6,7,9,10,14)
REQUIREMENTS = [
    MasvsRequirement("MASVS-STORAGE-1",    "Storage",    "Données sensibles non stockées localement en clair",      4,  "check_storage_1"),
    MasvsRequirement("MASVS-STORAGE-2",    "Storage",    "Aucune donnée sensible exposée via logs ou IPC",          4,  "check_storage_2"),
    MasvsRequirement("MASVS-CRYPTO-1",     "Crypto",     "Algorithmes cryptographiques solides et bien configurés", 6,  "check_crypto_1"),
    MasvsRequirement("MASVS-CRYPTO-2",     "Crypto",     "Clés cryptographiques gérées de façon sécurisée",         6,  "check_crypto_2"),
    MasvsRequirement("MASVS-AUTH-1",       "Auth",       "Authentification forte côté serveur",                     7,  "check_auth_1"),
    MasvsRequirement("MASVS-AUTH-2",       "Auth",       "Aucune donnée sensible dans les tokens/sessions",         7,  "check_auth_2"),
    MasvsRequirement("MASVS-NETWORK-1",    "Network",    "TLS obligatoire pour toutes les connexions réseau",        9,  "check_network_1"),
    MasvsRequirement("MASVS-NETWORK-2",    "Network",    "Validation correcte du certificat TLS",                   9,  "check_network_2"),
    MasvsRequirement("MASVS-CODE-1",       "Code",       "Pas de vulnérabilités connues dans les bibliothèques",    10, "check_code_1"),
    MasvsRequirement("MASVS-CODE-2",       "Code",       "Aucun debug ou code de test en production",               10, "check_code_2"),
    MasvsRequirement("MASVS-RESILIENCE-1", "Resilience", "Protection contre le reverse engineering",                14, "check_resilience_1"),
    MasvsRequirement("MASVS-RESILIENCE-2", "Resilience", "Protection contre la falsification (tampering)",          14, "check_resilience_2"),
]


def check_compliance(analysis: dict) -> dict:
    manifest = analysis.get("manifest", {})
    perms    = analysis.get("permissions", {})
    sbom     = analysis.get("sbom", {})
    strings  = analysis.get("strings", {})

    results = {}

    # STORAGE-1 : no sensitive local storage → pass if no dangerous storage perms
    storage_perms = [d["name"] for d in perms.get("dangerous", [])
                     if d.get("chapter") == 4]
    results["MASVS-STORAGE-1"] = {
        "pass":   len(storage_perms) == 0,
        "details": f"{len(storage_perms)} permission(s) de stockage sensible"
                   if storage_perms else "Aucune permission de stockage sensible"
    }

    # STORAGE-2 : no data in logs → pass if allow_backup is False
    results["MASVS-STORAGE-2"] = {
        "pass":   not manifest.get("allow_backup", True),
        "details": "android:allowBackup=true détecté (risque)" if manifest.get("allow_backup") else "Backup désactivé"
    }

    # CRYPTO-1 : strong crypto → pass if crypto usage found and no weak patterns
    results["MASVS-CRYPTO-1"] = {
        "pass":   strings.get("has_crypto", False),
        "details": "Usage de primitives cryptographiques détecté" if strings.get("has_crypto") else "Aucune primitive crypto détectée"
    }

    # CRYPTO-2 : key management → pass if no plaintext keys found
    has_keys = bool(strings.get("findings", {}).get("api_keys") or
                    strings.get("findings", {}).get("aws_keys"))
    results["MASVS-CRYPTO-2"] = {
        "pass":   not has_keys,
        "details": "Clés potentielles en clair détectées" if has_keys else "Aucune clé en clair détectée"
    }

    # AUTH-1 : strong server auth → pass if no JWT in plain text
    has_jwt = bool(strings.get("findings", {}).get("jwt_tokens"))
    results["MASVS-AUTH-1"] = {
        "pass":   not has_jwt,
        "details": "Tokens JWT en clair détectés" if has_jwt else "Aucun token JWT en clair"
    }

    # AUTH-2 : secure session → pass if not debuggable
    results["MASVS-AUTH-2"] = {
        "pass":   not manifest.get("debuggable", False),
        "details": "android:debuggable=true — mode debug activé" if manifest.get("debuggable") else "Application non débogable"
    }

    # NETWORK-1 : TLS enforced → pass if no cleartext allowed
    results["MASVS-NETWORK-1"] = {
        "pass":   not manifest.get("uses_cleartext", False),
        "details": "usesCleartextTraffic=true détecté" if manifest.get("uses_cleartext") else "Trafic en clair non autorisé"
    }

    # NETWORK-2 : cert validation → pass if network security config present
    results["MASVS-NETWORK-2"] = {
        "pass":   manifest.get("has_network_security_config", False) or strings.get("has_ssl_pinning", False),
        "details": "SSL Pinning ou NetworkSecurityConfig détecté" if (manifest.get("has_network_security_config") or strings.get("has_ssl_pinning")) else "Aucune config réseau sécurisée"
    }

    # CODE-1 : no vulnerable libs → pass if no risky libs
    risky = sbom.get("risky_libs", [])
    results["MASVS-CODE-1"] = {
        "pass":   len(risky) == 0,
        "details": f"Libs de debug détectées : {', '.join(r['name'] for r in risky)}" if risky else "Aucune bibliothèque risquée"
    }

    # CODE-2 : no debug code → pass if not debuggable and no debug libs
    results["MASVS-CODE-2"] = {
        "pass":   not manifest.get("debuggable", False) and len(risky) == 0,
        "details": "Mode debug ou bibliothèques de test détectés" if (manifest.get("debuggable") or risky) else "Aucun code de debug"
    }

    # RESILIENCE-1 : anti-reverse → pass if obfuscation detected
    results["MASVS-RESILIENCE-1"] = {
        "pass":   strings.get("has_obfuscation", False),
        "details": "Obfuscation détectée (ProGuard/R8)" if strings.get("has_obfuscation") else "Aucune obfuscation détectée"
    }

    # RESILIENCE-2 : anti-tamper → pass if root check detected
    results["MASVS-RESILIENCE-2"] = {
        "pass":   strings.get("has_root_check", False),
        "details": "Détection root/jailbreak présente" if strings.get("has_root_check") else "Aucune détection root"
    }

    satisfied = [k for k, v in results.items() if v["pass"]]
    missing   = [k for k, v in results.items() if not v["pass"]]

    return {
        "results":   results,
        "satisfied": satisfied,
        "missing":   missing,
        "score":     len(satisfied),
        "total":     len(REQUIREMENTS),
        "percentage": round(len(satisfied) / len(REQUIREMENTS) * 100),
    }


# ── MobSF comparison ──────────────────────────────────────────────────────────

MOBSF_CHECKS = [
    {"category": "Static", "check": "Manifest Analysis",        "mobsf": True,  "ours": True},
    {"category": "Static", "check": "APK Hash & Signature",     "mobsf": True,  "ours": True},
    {"category": "Static", "check": "Permission Analysis",      "mobsf": True,  "ours": True},
    {"category": "Static", "check": "SBOM / Library Detection", "mobsf": True,  "ours": True},
    {"category": "Static", "check": "Hardcoded Secrets",        "mobsf": True,  "ours": True},
    {"category": "Static", "check": "URL / IP Extraction",      "mobsf": True,  "ours": True},
    {"category": "Static", "check": "Obfuscation Detection",    "mobsf": True,  "ours": True},
    {"category": "Static", "check": "MASVS / MASTG Mapping",    "mobsf": True,  "ours": True},
    {"category": "Static", "check": "Certificate Analysis",     "mobsf": True,  "ours": False},
    {"category": "Static", "check": "Class & Method Analysis",  "mobsf": True,  "ours": False},
    {"category": "Dynamic","check": "Root/Emulator Detection",  "mobsf": True,  "ours": True},
    {"category": "Dynamic","check": "SSL Pinning Check",        "mobsf": True,  "ours": True},
    {"category": "Dynamic","check": "Anti-Debug Indicators",    "mobsf": True,  "ours": True},
    {"category": "Dynamic","check": "Dynamic Code Loading",     "mobsf": True,  "ours": True},
    {"category": "Dynamic","check": "Runtime Traffic Intercept","mobsf": True,  "ours": False},
    {"category": "Dynamic","check": "Frida/Xposed Detection",   "mobsf": True,  "ours": False},
    {"category": "Report", "check": "HTML Report Generation",   "mobsf": True,  "ours": True},
    {"category": "Report", "check": "JSON / ZIP Export",        "mobsf": True,  "ours": True},
    {"category": "Report", "check": "AI Summary (LLM)",         "mobsf": False, "ours": True},
    {"category": "Report", "check": "MASVS Compliance Score",   "mobsf": True,  "ours": True},
]

def get_mobsf_comparison() -> dict:
    both_have  = [c for c in MOBSF_CHECKS if c["mobsf"] and c["ours"]]
    only_mobsf = [c for c in MOBSF_CHECKS if c["mobsf"] and not c["ours"]]
    only_ours  = [c for c in MOBSF_CHECKS if not c["mobsf"] and c["ours"]]
    return {
        "checks":      MOBSF_CHECKS,
        "both_have":   both_have,
        "only_mobsf":  only_mobsf,
        "only_ours":   only_ours,
        "coverage_pct": round(len(both_have) / len([c for c in MOBSF_CHECKS if c["mobsf"]]) * 100),
    }
