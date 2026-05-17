import zipfile
import re
import struct


# ── Binary AXML helpers ────────────────────────────────────────────────────────

def _decode_axml(data: bytes) -> str:
    """Light-weight AXML → readable string extractor (no androguard required)."""
    result = []
    i = 0
    while i < len(data) - 1:
        b = data[i] & 0xFF
        n = data[i + 1] & 0xFF
        if 32 <= b <= 126 and n == 0:
            result.append(chr(b))
        i += 1
    return "".join(result)


def _first(text: str, pattern: str) -> str:
    m = re.search(pattern, text)
    return m.group(1) if m else "unknown"


def _all(text: str, pattern: str) -> list:
    return re.findall(pattern, text)


# ── Try pyaxmlparser first ─────────────────────────────────────────────────────

def _parse_with_pyaxmlparser(raw: bytes):
    try:
        from pyaxmlparser import APK
        return None  # APK-level, we'll handle below
    except ImportError:
        return None


# ── Main entry ────────────────────────────────────────────────────────────────

def parse_manifest(apk_path: str) -> dict:
    raw_manifest = None

    with zipfile.ZipFile(apk_path, "r") as z:
        if "AndroidManifest.xml" in z.namelist():
            raw_manifest = z.read("AndroidManifest.xml")

    if raw_manifest is None:
        return {"error": "AndroidManifest.xml not found"}

    # Try pyaxmlparser
    try:
        from pyaxmlparser import APK as PyAPK
        apk = PyAPK(apk_path)
        activities = list(apk.get_activities())
        services   = list(apk.get_services())
        receivers  = list(apk.get_receivers())
        providers  = list(apk.get_providers())

        # Check exported components
        xml_str = _decode_axml(raw_manifest)
        exported_acts = _all(xml_str, r'<activity[^>]*android:exported="true"[^>]*android:name="([^"]+)"')
        debug_flag = "android:debuggable=\"true\"" in xml_str or "debuggable" in xml_str.lower()
        backup_flag = "android:allowBackup=\"true\"" in xml_str

        return {
            "package_name":      apk.get_package(),
            "version_name":      apk.get_androidversion_name() or "unknown",
            "version_code":      apk.get_androidversion_code() or "unknown",
            "min_sdk":           apk.get_min_sdk_version() or "unknown",
            "target_sdk":        apk.get_target_sdk_version() or "unknown",
            "activities":        activities,
            "services":          services,
            "receivers":         receivers,
            "providers":         providers,
            "exported_activities": exported_acts,
            "debuggable":        debug_flag,
            "allow_backup":      backup_flag,
            "uses_cleartext":    "cleartext" in xml_str.lower(),
            "has_network_security_config": "network_security_config" in xml_str.lower(),
        }
    except Exception:
        pass

    # Fallback: decode AXML manually
    xml_str = _decode_axml(raw_manifest)
    return {
        "package_name":  _first(xml_str, r"package=([^\s\"']+)"),
        "version_name":  _first(xml_str, r"versionName=([^\s\"']+)"),
        "version_code":  _first(xml_str, r"versionCode=([^\s\"']+)"),
        "min_sdk":       _first(xml_str, r"minSdkVersion=([^\s\"']+)"),
        "target_sdk":    _first(xml_str, r"targetSdkVersion=([^\s\"']+)"),
        "activities":    _all(xml_str, r"activity[^\s]*\s+([a-zA-Z][a-zA-Z0-9_.]+)"),
        "services":      _all(xml_str, r"service[^\s]*\s+([a-zA-Z][a-zA-Z0-9_.]+)"),
        "receivers":     _all(xml_str, r"receiver[^\s]*\s+([a-zA-Z][a-zA-Z0-9_.]+)"),
        "providers":     [],
        "exported_activities": [],
        "debuggable":    "debuggable" in xml_str.lower(),
        "allow_backup":  "allowBackup" in xml_str,
        "uses_cleartext": "cleartext" in xml_str.lower(),
        "has_network_security_config": "network_security_config" in xml_str.lower(),
    }
