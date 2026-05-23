import os
import uuid
import json
from datetime import datetime
from flask import (Flask, render_template, request, jsonify,
                   send_file, abort)
from modules.apk_analyzer import analyze_apk

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB

UPLOAD_DIR  = "uploads"
REPORTS_DIR = "reports"
os.makedirs(UPLOAD_DIR,  exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


# ── Pages ──────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── API: analyze ───────────────────────────────────────────────────────────────

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    if "apk" not in request.files:
        return jsonify({"error": "Aucun fichier APK fourni"}), 400

    file = request.files["apk"]
    if not file.filename:
        return jsonify({"error": "Nom de fichier invalide"}), 400

    # Save APK
    task_id  = str(uuid.uuid4())
    apk_path = os.path.join(UPLOAD_DIR, f"{task_id}.apk")
    file.save(apk_path)

    try:
        # Run analysis
        results = analyze_apk(apk_path, filename=file.filename)

        # Persist results JSON
        json_path = os.path.join(REPORTS_DIR, f"{task_id}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

        # Generate HTML report
        html = _build_html_report(results, task_id)
        html_path = os.path.join(REPORTS_DIR, f"{task_id}.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

        results["task_id"] = task_id
        return jsonify(results)

    finally:
        if os.path.exists(apk_path):
            os.remove(apk_path)


# ── API: download report ───────────────────────────────────────────────────────

@app.route("/report/<task_id>")
def download_report(task_id):
    html_path = os.path.join(REPORTS_DIR, f"{task_id}.html")
    if not os.path.exists(html_path):
        abort(404)
    return send_file(html_path, as_attachment=True,
                     download_name="rapport_audit.html")


@app.route("/report-json/<task_id>")
def download_json(task_id):
    json_path = os.path.join(REPORTS_DIR, f"{task_id}.json")
    if not os.path.exists(json_path):
        abort(404)
    return send_file(json_path, as_attachment=True,
                     download_name="rapport_audit.json")


# ── HTML Report Builder ────────────────────────────────────────────────────────

def _esc(s):
    if s is None: return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def _badge(risk):
    colors = {
        "HIGH":    ("FBEDED","8B2020","F0A0A0"),
        "MEDIUM":  ("FBF4E0","7A5200","F0C97A"),
        "LOW":     ("EAF8F2","1A6B48","8DD5B0"),
        "NORMAL":  ("EAF8F2","1A6B48","8DD5B0"),
        "UNKNOWN": ("F5F5F5","6B7C8D","C8DDF0"),
        "CRITIQUE":("FBEDED","8B2020","F0A0A0"),
        "ÉLEVÉ":   ("FBF4E0","7A5200","F0C97A"),
        "MOYEN":   ("FFF8DC","7A5200","F0C97A"),
        "FAIBLE":  ("EAF8F2","1A6B48","8DD5B0"),
    }
    bg, text, border = colors.get(risk, ("F5F5F5","6B7C8D","C8DDF0"))
    return f"<span style='background:#{bg};color:#{text};border:1px solid #{border};padding:2px 10px;border-radius:99px;font-size:11px;font-weight:700'>{_esc(risk)}</span>"

def _check_badge(passed: bool):
    if passed:
        return "<span style='background:#EAF8F2;color:#1A6B48;border:1px solid #8DD5B0;padding:2px 10px;border-radius:99px;font-size:11px;font-weight:700'>Verifie</span>"
    return "<span style='background:#FBEDED;color:#8B2020;border:1px solid #F0A0A0;padding:2px 10px;border-radius:99px;font-size:11px;font-weight:700'>Manquant</span>"

def _build_html_report(r: dict, task_id: str) -> str:
    m     = r.get("manifest", {})
    perms = r.get("permissions", {})
    sbom  = r.get("sbom", {})
    strs  = r.get("strings", {})
    masvs = r.get("masvs", {})
    hsh   = r.get("hashes", {})
    ai    = r.get("ai", {})
    mobsf = r.get("mobsf_comparison", {})
    score = masvs.get("score", 0)
    total = masvs.get("total", 12)
    risk  = r.get("overall_risk_level", "MOYEN")
    risk_colors = {"CRITIQUE":"#8B2020","ÉLEVÉ":"#7A5200","MOYEN":"#7A5200","FAIBLE":"#1A6B48"}
    rc = risk_colors.get(risk, "#6B7C8D")

    h = []
    h.append(f"""<!DOCTYPE html><html lang='fr'><head>
<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Rapport d'audit — {_esc(m.get('package_name',''))}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;background:#F2F7FB;color:#1E2D3D;font-size:14px}}
.header{{background:linear-gradient(135deg,#5BA4D8,#90C8EB);color:white;padding:24px 20px}}
.header h1{{font-size:21px;font-weight:700;margin-bottom:3px}}
.header p{{font-size:12px;opacity:.85;margin-bottom:12px}}
.pill{{display:inline-block;background:white;padding:5px 18px;border-radius:99px;font-weight:700;font-size:14px;color:{rc}}}
.container{{padding:16px;max-width:960px;margin:0 auto}}
.card{{background:white;border-radius:14px;padding:16px;margin-bottom:14px;box-shadow:0 2px 8px rgba(91,164,216,.10)}}
.card-label{{font-size:10px;font-weight:700;letter-spacing:.12em;color:#A0ADB8;text-transform:uppercase;margin-bottom:10px}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px}}
.stat{{background:white;border-radius:12px;padding:14px;text-align:center;box-shadow:0 2px 8px rgba(91,164,216,.10)}}
.stat-val{{font-size:26px;font-weight:700;color:#3D84BC}}
.stat-label{{font-size:11px;color:#6B7C8D;margin-top:3px}}
.row{{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #E4EDF5;font-size:13px}}
.row:last-child{{border-bottom:none}}
.label{{color:#6B7C8D;flex:1}}.value{{font-weight:600;flex:2;text-align:right;word-break:break-all}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#A8D5F5;color:#1E2D3D;padding:8px 10px;text-align:left;font-weight:700;font-size:11px}}
td{{padding:7px 10px;border-bottom:1px solid #E4EDF5;vertical-align:top}}
tr:nth-child(even) td{{background:#F8FBFD}}
pre{{background:#192434;color:#C0DFFF;padding:12px;border-radius:10px;font-size:11px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;line-height:1.6}}
ul{{padding-left:18px;line-height:1.8;font-size:13px}}
.ai-box{{background:linear-gradient(135deg,#D6EDFB,#FDE8F0);border-radius:12px;padding:16px;margin-bottom:14px}}
.footer{{text-align:center;padding:20px;color:#A0ADB8;font-size:11px}}
</style></head><body>""")

    # HEADER
    h.append(f"""<div class='header'>
<h1>Evidence Collector &amp; Compliance Pack</h1>
<p>Rapport d'audit statique &amp; dynamique — MASVS/MASTG · {_esc(r.get('analyzed_at',''))}</p>
<div class='pill'>Risque global : {_esc(risk)}</div>&nbsp;
<div class='pill'>MASVS : {score}/{total}</div>
</div><div class='container'>""")

    # STATS GRID
    h.append(f"""<div class='grid'>
<div class='stat'><div class='stat-val'>{perms.get('total',0)}</div><div class='stat-label'>Permissions</div></div>
<div class='stat'><div class='stat-val' style='color:#8B2020'>{perms.get('high_count',0)}</div><div class='stat-label'>Perms. dangereuses</div></div>
<div class='stat'><div class='stat-val'>{sbom.get('total',0)}</div><div class='stat-label'>Librairies (SBOM)</div></div>
<div class='stat'><div class='stat-val' style='color:{rc}'>{score}/{total}</div><div class='stat-label'>Score MASVS</div></div>
</div>""")

    # AI SUMMARY
    if ai:
        ai_risk = _esc(ai.get("niveau_risque",""))
        h.append(f"""<div class='ai-box'>
<div style='font-size:10px;font-weight:700;letter-spacing:.12em;color:#3D84BC;text-transform:uppercase;margin-bottom:8px'>Analyse IA — Gemini Flash</div>
<p style='font-size:13px;line-height:1.7;margin-bottom:10px'>{_esc(ai.get('resume_executif',''))}</p>
<div style='display:flex;gap:8px;flex-wrap:wrap'>""")
        for r_ in ai.get("recommandations",[]):
            h.append(f"<div style='background:white;border-radius:8px;padding:6px 12px;font-size:12px;color:#3D84BC'>{_esc(r_)}</div>")
        h.append("</div></div>")

    # APP INFO
    h.append(f"""<div class='card'><div class='card-label'>Informations APK</div>
<div class='row'><span class='label'>Fichier</span><span class='value'>{_esc(r.get('filename',''))}</span></div>
<div class='row'><span class='label'>Package</span><span class='value'>{_esc(m.get('package_name',''))}</span></div>
<div class='row'><span class='label'>Version</span><span class='value'>{_esc(m.get('version_name',''))} (code {_esc(m.get('version_code',''))})</span></div>
<div class='row'><span class='label'>SDK Min / Target</span><span class='value'>{_esc(m.get('min_sdk',''))} / {_esc(m.get('target_sdk',''))}</span></div>
<div class='row'><span class='label'>Taille</span><span class='value'>{hsh.get('size_mb',0)} MB</span></div>
<div class='row'><span class='label'>SHA-256</span><span class='value' style='font-size:11px;font-family:monospace'>{_esc(hsh.get('sha256',''))}</span></div>
<div class='row'><span class='label'>MD5</span><span class='value' style='font-family:monospace'>{_esc(hsh.get('md5',''))}</span></div>
<div class='row'><span class='label'>Débogage activé</span><span class='value'>{_badge('HIGH' if m.get('debuggable') else 'NORMAL')}</span></div>
<div class='row'><span class='label'>Backup autorisé</span><span class='value'>{_badge('MEDIUM' if m.get('allow_backup') else 'NORMAL')}</span></div>
<div class='row'><span class='label'>Trafic texte clair</span><span class='value'>{_badge('HIGH' if m.get('uses_cleartext') else 'NORMAL')}</span></div>
</div>""")

    # PERMISSIONS
    h.append(f"<div class='card'><div class='card-label'>Permissions ({perms.get('total',0)} au total — {perms.get('high_count',0)} dangereuses)</div>")
    h.append("<table><tr><th>Permission</th><th>Risque</th><th>MASVS</th><th>Chapitre</th></tr>")
    for p in perms.get("dangerous",[]):
        h.append(f"<tr><td style='font-weight:600;color:#8B2020'>{_esc(p['name'])}</td><td>{_badge(p['risk'])}</td><td>{_esc(p.get('masvs',''))}</td><td>{p.get('chapter','')}</td></tr>")
    for p in perms.get("normal",[]):
        h.append(f"<tr><td style='color:#3D84BC'>{_esc(p['name'])}</td><td>{_badge('NORMAL')}</td><td>—</td><td>—</td></tr>")
    h.append("</table></div>")

    # SBOM
    h.append(f"<div class='card'><div class='card-label'>SBOM — {sbom.get('total',0)} bibliothèques · {sbom.get('native_count',0)} libs natives · {sbom.get('dex_count',0)} fichiers DEX</div>")
    if sbom.get("libraries"):
        h.append("<table><tr><th>Bibliothèque</th><th>Vendor</th><th>Type</th><th>Statut</th></tr>")
        for lib in sbom["libraries"]:
            flag = _badge("HIGH") if lib.get("risky") else _badge("NORMAL")
            h.append(f"<tr><td>{_esc(lib['name'])}</td><td>{_esc(lib.get('vendor',''))}</td><td>{_esc(lib.get('type',''))}</td><td>{flag}</td></tr>")
        h.append("</table>")
    if sbom.get("native_libs"):
        h.append("<br><table><tr><th>Lib native (.so)</th><th>Taille</th></tr>")
        for nl in sbom["native_libs"]:
            h.append(f"<tr><td style='font-family:monospace;font-size:11px'>{_esc(nl['path'])}</td><td>{nl.get('size_kb',0)} KB</td></tr>")
        h.append("</table>")
    h.append("</div>")

    # STRINGS / DYNAMIC INDICATORS
    strs_findings = strs.get("findings", {})
    dyn = strs.get("dynamic_indicators", {})
    h.append(f"<div class='card'><div class='card-label'>Analyse statique avancée — Indicateurs dynamiques</div>")
    h.append("<table><tr><th>Indicateur</th><th>Présence</th><th>Éléments détectés</th></tr>")
    checks = [
        ("Obfuscation (ProGuard/R8)", strs.get("has_obfuscation"), dyn.get("obfuscation",[])),
        ("SSL Pinning",              strs.get("has_ssl_pinning"), dyn.get("ssl_pinning",[])),
        ("Détection root/jailbreak", strs.get("has_root_check"),  dyn.get("root_detection",[])),
        ("Anti-débogage",            bool(dyn.get("anti_debug")), dyn.get("anti_debug",[])),
        ("Détection émulateur",      bool(dyn.get("emulator_detection")), dyn.get("emulator_detection",[])),
        ("Chargement dynamique",     bool(dyn.get("dynamic_code_loading")), dyn.get("dynamic_code_loading",[])),
        ("Usage crypto",             strs.get("has_crypto"),      dyn.get("crypto_usage",[])),
        ("Réflexion Java",           bool(dyn.get("reflection")), dyn.get("reflection",[])),
    ]
    for label, present, items in checks:
        badge = _badge("NORMAL") if present else _badge("MEDIUM")
        h.append(f"<tr><td>{_esc(label)}</td><td>{badge}</td><td style='font-size:11px;color:#6B7C8D'>{', '.join(_esc(i) for i in items[:5])}</td></tr>")
    h.append("</table>")
    if strs_findings:
        h.append("<br><table><tr><th>Type de secret détecté</th><th>Exemples (anonymisés)</th></tr>")
        for k, vals in strs_findings.items():
            h.append(f"<tr><td>{_badge('HIGH' if k in ('api_keys','aws_keys','private_keys','jwt_tokens') else 'LOW')} <b>{_esc(k)}</b></td><td style='font-size:11px;font-family:monospace'>{', '.join(_esc(v) for v in vals[:3])}</td></tr>")
        h.append("</table>")
    h.append("</div>")

    # MASVS
    masvs_results = masvs.get("results", {})
    h.append(f"""<div class='card'><div class='card-label'>Conformité MASVS / MASTG — {score}/{total} exigences ({masvs.get('percentage',0)}%)</div>
<div style='text-align:center;padding:12px;background:#F2F7FB;border-radius:10px;margin-bottom:12px'>
<div style='font-size:36px;font-weight:700;color:{rc}'>{score}/{total}</div>
<div style='font-size:12px;color:#6B7C8D'>exigences satisfaites</div></div>
<table><tr><th>Exigence</th><th>Description</th><th>Chap.</th><th>Statut</th><th>Détails</th></tr>""")
    from modules.masvs_mapper import REQUIREMENTS
    for req in REQUIREMENTS:
        res = masvs_results.get(req.id, {})
        passed = res.get("pass", False)
        h.append(f"<tr><td><b>{_esc(req.id)}</b></td><td>{_esc(req.description)}</td><td>{req.chapter}</td><td>{_check_badge(passed)}</td><td style='font-size:11px;color:#6B7C8D'>{_esc(res.get('details',''))}</td></tr>")
    h.append("</table></div>")

    # MOBSF COMPARISON
    h.append("<div class='card'><div class='card-label'>Comparaison avec MobSF</div>")
    h.append("<table><tr><th>Vérification</th><th>Catégorie</th><th>MobSF</th><th>Evidence Collector</th></tr>")
    for c in mobsf.get("checks", []):
        ok_icon = lambda b: "Oui" if b else "Non"
        m_style = "color:#1A6B48;font-weight:600" if c["mobsf"] else "color:#8B2020"
        o_style = "color:#1A6B48;font-weight:600" if c["ours"]  else "color:#6B7C8D"
        h.append(f"<tr><td>{_esc(c['check'])}</td><td><span style='font-size:11px;color:#6B7C8D'>{_esc(c['category'])}</span></td><td style='{m_style}'>{ok_icon(c['mobsf'])}</td><td style='{o_style}'>{ok_icon(c['ours'])}</td></tr>")
    cov = mobsf.get("coverage_pct", 0)
    h.append(f"</table><p style='margin-top:10px;font-size:12px;color:#6B7C8D'>Notre outil couvre <b>{cov}%</b> des vérifications MobSF. Avantage exclusif : <b>analyse IA (Gemini)</b> non disponible dans MobSF.</p></div>")

    # AI detail
    if ai:
        def ai_list(key):
            items = ai.get(key, [])
            if not items: return "<li>—</li>"
            return "".join(f"<li>{_esc(i)}</li>" for i in items)
        h.append(f"""<div class='card'><div class='card-label'>Détail de l'analyse IA</div>
<div class='row'><span class='label'>Niveau de risque IA</span><span class='value'>{_badge(ai.get('niveau_risque',''))}</span></div>
<br>
<div style='margin-bottom:10px'><b style='color:#3D84BC'>Points forts</b><ul style='margin-top:6px'>{ai_list('points_forts')}</ul></div>
<div style='margin-bottom:10px'><b style='color:#8B2020'>Vulnérabilités</b><ul style='margin-top:6px'>{ai_list('vulnerabilites')}</ul></div>
<div style='margin-bottom:10px'><b style='color:#1A6B48'>Recommandations</b><ul style='margin-top:6px'>{ai_list('recommandations')}</ul></div>
<div style='margin-bottom:6px;font-size:12px;color:#6B7C8D'><b>Analyse MASVS :</b> {_esc(ai.get('masvs_analyse',''))}</div>
<div style='font-size:12px;color:#6B7C8D'><b>Vs MobSF :</b> {_esc(ai.get('comparaison_mobsf',''))}</div>
</div>""")

    h.append(f"<div class='footer'>Evidence Collector &amp; Compliance Pack — ENSA Marrakech<br>Rapport généré le {_esc(r.get('analyzed_at',''))}</div>")
    h.append("</div></body></html>")
    return "".join(h)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
