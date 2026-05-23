import os
from datetime import datetime

from .apk_hasher        import compute_hashes
from .manifest_parser   import parse_manifest
from .permission_analyzer import analyze_permissions
from .sbom_generator    import generate_sbom
from .strings_analyzer  import analyze_strings
from .masvs_mapper      import check_compliance, get_mobsf_comparison
from .gemini_client     import analyze_with_ai


def analyze_apk(apk_path: str, filename: str = "app.apk") -> dict:
    """Run all analysis modules and return aggregated results."""

    result = {
        "filename":    filename,
        "analyzed_at": datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
        "error":       None,
    }

    try:
        # Step 1: Hashes
        result["hashes"] = compute_hashes(apk_path)

        # Step 2: Manifest
        result["manifest"] = parse_manifest(apk_path)

        # Step 3: Permissions
        result["permissions"] = analyze_permissions(apk_path)

        # Step 4: SBOM
        result["sbom"] = generate_sbom(apk_path)

        # Step 5: Strings + dynamic indicators
        result["strings"] = analyze_strings(apk_path)

        # Step 6: MASVS compliance
        result["masvs"] = check_compliance(result)

        # Step 7: MobSF comparison (static data)
        result["mobsf_comparison"] = get_mobsf_comparison()

        # Step 8: AI analysis
        result["ai"] = analyze_with_ai(result)

        # Overall risk score
        perms_score  = result["permissions"].get("risk_score", 0)
        masvs_pct    = result["masvs"].get("percentage", 100)
        string_sev   = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 5}.get(
                            result["strings"].get("severity", "LOW"), 5)
        result["overall_risk_score"] = min(100, perms_score + string_sev + max(0, (100 - masvs_pct) // 3))
        result["overall_risk_level"]  = (
            "CRITIQUE" if result["overall_risk_score"] >= 70 else
            "ÉLEVÉ"    if result["overall_risk_score"] >= 45 else
            "MOYEN"    if result["overall_risk_score"] >= 20 else
            "FAIBLE"
        )

    except Exception as e:
        result["error"] = str(e)
        import traceback
        result["traceback"] = traceback.format_exc()

    return result
