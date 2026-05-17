import zipfile, re

# ── MASVS-mapped dangerous permissions ────────────────────────────────────────
DANGEROUS_PERMS = {
    "READ_CONTACTS":           {"risk": "HIGH",   "masvs": "MASVS-STORAGE-1",  "chapter": 4},
    "WRITE_CONTACTS":          {"risk": "HIGH",   "masvs": "MASVS-STORAGE-1",  "chapter": 4},
    "GET_ACCOUNTS":            {"risk": "MEDIUM", "masvs": "MASVS-AUTH-1",     "chapter": 7},
    "READ_CALL_LOG":           {"risk": "HIGH",   "masvs": "MASVS-STORAGE-1",  "chapter": 4},
    "WRITE_CALL_LOG":          {"risk": "HIGH",   "masvs": "MASVS-STORAGE-1",  "chapter": 4},
    "READ_CALENDAR":           {"risk": "MEDIUM", "masvs": "MASVS-STORAGE-1",  "chapter": 4},
    "WRITE_CALENDAR":          {"risk": "MEDIUM", "masvs": "MASVS-STORAGE-1",  "chapter": 4},
    "READ_EXTERNAL_STORAGE":   {"risk": "HIGH",   "masvs": "MASVS-STORAGE-2",  "chapter": 4},
    "WRITE_EXTERNAL_STORAGE":  {"risk": "HIGH",   "masvs": "MASVS-STORAGE-2",  "chapter": 4},
    "CAMERA":                  {"risk": "HIGH",   "masvs": "MASVS-STORAGE-1",  "chapter": 4},
    "RECORD_AUDIO":            {"risk": "HIGH",   "masvs": "MASVS-STORAGE-1",  "chapter": 4},
    "READ_PHONE_STATE":        {"risk": "HIGH",   "masvs": "MASVS-STORAGE-1",  "chapter": 4},
    "CALL_PHONE":              {"risk": "HIGH",   "masvs": "MASVS-AUTH-1",     "chapter": 7},
    "ACCESS_FINE_LOCATION":    {"risk": "HIGH",   "masvs": "MASVS-STORAGE-1",  "chapter": 4},
    "ACCESS_COARSE_LOCATION":  {"risk": "MEDIUM", "masvs": "MASVS-STORAGE-1",  "chapter": 4},
    "BODY_SENSORS":            {"risk": "HIGH",   "masvs": "MASVS-STORAGE-1",  "chapter": 4},
    "SEND_SMS":                {"risk": "HIGH",   "masvs": "MASVS-NETWORK-1",  "chapter": 9},
    "RECEIVE_SMS":             {"risk": "HIGH",   "masvs": "MASVS-NETWORK-1",  "chapter": 9},
    "MANAGE_EXTERNAL_STORAGE": {"risk": "HIGH",   "masvs": "MASVS-STORAGE-2",  "chapter": 4},
    "USE_BIOMETRIC":           {"risk": "LOW",    "masvs": "MASVS-AUTH-1",     "chapter": 7},
    "REQUEST_INSTALL_PACKAGES":{"risk": "HIGH",   "masvs": "MASVS-CODE-1",     "chapter": 10},
    "SYSTEM_ALERT_WINDOW":     {"risk": "HIGH",   "masvs": "MASVS-RESILIENCE-1","chapter":14},
    "PACKAGE_USAGE_STATS":     {"risk": "MEDIUM", "masvs": "MASVS-STORAGE-1",  "chapter": 4},
    "READ_PRIVILEGED_PHONE_STATE": {"risk":"HIGH","masvs":"MASVS-STORAGE-1",   "chapter": 4},
}

NORMAL_PERMS = {
    "INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE",
    "BLUETOOTH", "BLUETOOTH_ADMIN", "CHANGE_NETWORK_STATE",
    "CHANGE_WIFI_STATE", "VIBRATE", "WAKE_LOCK", "RECEIVE_BOOT_COMPLETED",
    "FLASHLIGHT", "NFC", "FOREGROUND_SERVICE", "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "POST_NOTIFICATIONS", "SCHEDULE_EXACT_ALARM", "USE_FINGERPRINT",
}

def _extract_perms_from_zip(apk_path: str) -> list:
    with zipfile.ZipFile(apk_path, "r") as z:
        raw = z.read("AndroidManifest.xml")
    # Try pyaxmlparser
    try:
        from pyaxmlparser import APK
        apk = APK(apk_path)
        return list(apk.get_permissions())
    except Exception:
        pass
    # Fallback: raw decode
    text = "".join(
        chr(raw[i] & 0xFF)
        for i in range(len(raw) - 1)
        if 32 <= (raw[i] & 0xFF) <= 126 and (raw[i + 1] & 0xFF) == 0
    )
    perms = re.findall(r"android\.permission\.([A-Z_]+)", text)
    return [f"android.permission.{p}" for p in perms]


def analyze_permissions(apk_path: str) -> dict:
    raw_list = _extract_perms_from_zip(apk_path)
    dangerous = []
    normal    = []
    unknown   = []

    for perm in raw_list:
        name = perm.replace("android.permission.", "").split(".")[-1]
        if name in DANGEROUS_PERMS:
            dangerous.append({
                "name": name,
                "full": perm,
                **DANGEROUS_PERMS[name]
            })
        elif name in NORMAL_PERMS:
            normal.append({"name": name, "full": perm, "risk": "NORMAL"})
        else:
            unknown.append({"name": name, "full": perm, "risk": "UNKNOWN"})

    # Risk score
    high_count   = sum(1 for d in dangerous if d["risk"] == "HIGH")
    medium_count = sum(1 for d in dangerous if d["risk"] == "MEDIUM")
    risk_score   = min(100, high_count * 15 + medium_count * 7)

    return {
        "total":        len(raw_list),
        "dangerous":    dangerous,
        "normal":       normal,
        "unknown":      unknown,
        "high_count":   high_count,
        "medium_count": medium_count,
        "risk_score":   risk_score,
    }
