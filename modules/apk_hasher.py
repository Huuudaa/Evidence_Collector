import hashlib
import os

def compute_hashes(apk_path: str) -> dict:
    """Compute SHA-256, MD5 and file size of the APK."""
    sha256 = hashlib.sha256()
    md5    = hashlib.md5()
    size   = os.path.getsize(apk_path)

    with open(apk_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
            md5.update(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "md5":    md5.hexdigest(),
        "size_bytes": size,
        "size_kb":    round(size / 1024, 2),
        "size_mb":    round(size / (1024 * 1024), 3),
    }
