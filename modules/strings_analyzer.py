import zipfile
import re
from typing import Dict, List

# Patterns à détecter
PATTERNS = {
    "urls":          r'https?://[^\s\x00-\x1F"\'<>]{8,}',
    "emails":        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    "ip_addresses":  r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b',
    "api_keys":      r'(?i)(?:api[_-]?key|apikey|secret|token|auth)["\s:=]+([A-Za-z0-9\-_]{16,})',
    "aws_keys":      r'AKIA[0-9A-Z]{16}',
    "jwt_tokens":    r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',
    "private_keys":  r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    "google_keys":   r'AIza[0-9A-Za-z\-_]{35}',
    "firebase_urls": r'https://[a-z0-9\-]+\.firebaseio\.com',
}

# Indicateurs dynamiques (présents dans le code statique)
DYNAMIC_INDICATORS = {
    "root_detection":       ["su", "busybox", "supersu", "magisk", "rootbeer"],
    "ssl_pinning":          ["CertificatePinner", "SSLPinning", "PublicKeyPins", "TrustManagerImpl"],
    "anti_debug":           ["isDebuggerConnected", "DEBUGGABLE", "ptrace"],
    "emulator_detection":   ["isEmulator", "Build.FINGERPRINT", "goldfish", "Emulator"],
    "obfuscation":          ["proguard", "r8", "dexguard"],
    "dynamic_code_loading": ["DexClassLoader", "loadDex", "PathClassLoader"],
    "reflection":           ["Class.forName", "getDeclaredMethod", "invoke"],
    "crypto_usage":         ["AES", "RSA", "MessageDigest", "KeyStore", "Cipher"],
}

def _read_strings_from_dex(apk_path: str, max_bytes=4_000_000) -> str:
    """Read printable strings from all .dex files in the APK."""
    combined = []
    with zipfile.ZipFile(apk_path, "r") as z:
        for entry in z.infolist():
            if entry.filename.endswith(".dex"):
                raw = z.read(entry.filename)[:max_bytes]
                # Extract printable ASCII runs of length >= 6
                chunk = re.findall(rb'[\x20-\x7E]{6,}', raw)
                combined.extend(c.decode("ascii", errors="ignore") for c in chunk)
    return "\n".join(combined)


def analyze_strings(apk_path: str) -> dict:
    text = _read_strings_from_dex(apk_path)

    findings: Dict[str, List[str]] = {}
    for key, pattern in PATTERNS.items():
        matches = list(set(re.findall(pattern, text)))[:30]  # cap at 30
        if matches:
            findings[key] = matches

    # Anonymize sensitive ones for display
    display = {}
    for key, vals in findings.items():
        if key in ("api_keys", "aws_keys", "jwt_tokens", "private_keys"):
            display[key] = [v[:8] + "..." + v[-4:] if len(v) > 12 else "***" for v in vals]
        else:
            display[key] = vals

    # Dynamic indicators
    dynamic_hits = {}
    for category, keywords in DYNAMIC_INDICATORS.items():
        found = [kw for kw in keywords if kw in text]
        if found:
            dynamic_hits[category] = found

    severity = "LOW"
    if "private_keys" in findings or "aws_keys" in findings:
        severity = "CRITICAL"
    elif "api_keys" in findings or "jwt_tokens" in findings:
        severity = "HIGH"
    elif len(findings) > 3:
        severity = "MEDIUM"

    return {
        "findings":        display,
        "finding_types":   list(findings.keys()),
        "dynamic_indicators": dynamic_hits,
        "severity":        severity,
        "has_ssl_pinning": "ssl_pinning" in dynamic_hits,
        "has_root_check":  "root_detection" in dynamic_hits,
        "has_obfuscation": "obfuscation" in dynamic_hits,
        "has_crypto":      "crypto_usage" in dynamic_hits,
        "url_count":       len(findings.get("urls", [])),
    }
