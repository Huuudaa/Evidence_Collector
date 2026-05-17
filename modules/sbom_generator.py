import zipfile
import re
from typing import List, Dict

# ── Known library fingerprints ─────────────────────────────────────────────────
KNOWN_LIBS = {
    "okhttp":      {"name": "OkHttp",       "vendor": "Square",      "type": "Network"},
    "retrofit":    {"name": "Retrofit",      "vendor": "Square",      "type": "Network"},
    "gson":        {"name": "Gson",          "vendor": "Google",      "type": "Serialization"},
    "glide":       {"name": "Glide",         "vendor": "BumpTech",    "type": "Image"},
    "picasso":     {"name": "Picasso",       "vendor": "Square",      "type": "Image"},
    "rxjava":      {"name": "RxJava",        "vendor": "ReactiveX",   "type": "Reactive"},
    "firebase":    {"name": "Firebase",      "vendor": "Google",      "type": "Cloud"},
    "room":        {"name": "Room",          "vendor": "AndroidX",    "type": "Database"},
    "dagger":      {"name": "Dagger",        "vendor": "Google",      "type": "DI"},
    "hilt":        {"name": "Hilt",          "vendor": "Google",      "type": "DI"},
    "timber":      {"name": "Timber",        "vendor": "JakeWharton", "type": "Logging"},
    "lottie":      {"name": "Lottie",        "vendor": "Airbnb",      "type": "Animation"},
    "volley":      {"name": "Volley",        "vendor": "Google",      "type": "Network"},
    "fresco":      {"name": "Fresco",        "vendor": "Meta",        "type": "Image"},
    "realm":       {"name": "Realm",         "vendor": "MongoDB",     "type": "Database"},
    "sqlcipher":   {"name": "SQLCipher",     "vendor": "Zetetic",     "type": "Encrypted DB"},
    "bouncycastle":{"name": "BouncyCastle",  "vendor": "Legion",      "type": "Crypto"},
    "conscrypt":   {"name": "Conscrypt",     "vendor": "Google",      "type": "TLS"},
    "stetho":      {"name": "Stetho",        "vendor": "Meta",        "type": "Debug"},
    "leakcanary":  {"name": "LeakCanary",    "vendor": "Square",      "type": "Debug"},
    "mockito":     {"name": "Mockito",       "vendor": "Mockito",     "type": "Testing"},
    "kotlin":      {"name": "Kotlin",        "vendor": "JetBrains",   "type": "Language"},
    "coroutines":  {"name": "Coroutines",    "vendor": "JetBrains",   "type": "Async"},
    "navigation":  {"name": "Navigation",    "vendor": "AndroidX",    "type": "Navigation"},
    "compose":     {"name": "Compose",       "vendor": "AndroidX",    "type": "UI"},
    "coil":        {"name": "Coil",          "vendor": "Coil-kt",     "type": "Image"},
    "moshi":       {"name": "Moshi",         "vendor": "Square",      "type": "Serialization"},
    "koin":        {"name": "Koin",          "vendor": "Koin",        "type": "DI"},
    "exoplayer":   {"name": "ExoPlayer",     "vendor": "Google",      "type": "Media"},
    "crashlytics": {"name": "Crashlytics",   "vendor": "Google",      "type": "Analytics"},
    "amplitude":   {"name": "Amplitude",     "vendor": "Amplitude",   "type": "Analytics"},
    "segment":     {"name": "Segment",       "vendor": "Twilio",      "type": "Analytics"},
    "admob":       {"name": "AdMob",         "vendor": "Google",      "type": "Ads"},
    "facebook":    {"name": "Facebook SDK",  "vendor": "Meta",        "type": "Social"},
    "twitter":     {"name": "Twitter SDK",   "vendor": "Twitter",     "type": "Social"},
    "stripe":      {"name": "Stripe",        "vendor": "Stripe",      "type": "Payment"},
    "braintree":   {"name": "Braintree",     "vendor": "PayPal",      "type": "Payment"},
    "trustedevents": {"name": "TrustedEvents","vendor": "Unknown",    "type": "Analytics"},
}

# Debug/risky libraries
RISKY_LIBS = {"stetho", "leakcanary", "mockito"}


def generate_sbom(apk_path: str) -> dict:
    detected     = {}
    native_libs  = []
    dex_files    = []
    zip_entries  = []

    with zipfile.ZipFile(apk_path, "r") as z:
        for entry in z.infolist():
            name_lower = entry.filename.lower()
            zip_entries.append(entry.filename)

            if name_lower.startswith("lib/") and name_lower.endswith(".so"):
                native_libs.append({
                    "path": entry.filename,
                    "size_kb": round(entry.file_size / 1024, 1)
                })

            if name_lower.endswith(".dex"):
                dex_files.append(entry.filename)

            for key, info in KNOWN_LIBS.items():
                if key in name_lower:
                    detected[key] = info

    # Flag risky ones
    libs = []
    for key, info in detected.items():
        libs.append({
            **info,
            "risky": key in RISKY_LIBS
        })

    return {
        "libraries":     libs,
        "total":         len(libs),
        "native_libs":   native_libs,
        "native_count":  len(native_libs),
        "dex_files":     dex_files,
        "dex_count":     len(dex_files),
        "risky_libs":    [l for l in libs if l.get("risky")],
        "total_entries": len(zip_entries),
    }
