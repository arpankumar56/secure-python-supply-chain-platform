import os
from flask import Flask, render_template, request, jsonify
from scanner import scan_package, parse_requirements, scan_python_source
from analytics import get_demo_analytics

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB upload limit


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/scan")
def api_scan():
    """Scan a package name/version or a requirements.txt upload."""
    try:
        package_name = (request.form.get("package_name") or "").strip()
        package_version = (request.form.get("package_version") or "").strip()
        requirements_file = request.files.get("requirements_file")

        packages = []
        if requirements_file and requirements_file.filename:
            if not requirements_file.filename.lower().endswith(".txt"):
                return jsonify({"error": "Please upload a .txt requirements file."}), 400
            raw = requirements_file.read().decode("utf-8", errors="replace")
            packages = parse_requirements(raw)
            if not packages:
                return jsonify({"error": "No supported package entries found in the requirements file."}), 400
        elif package_name:
            packages = [{"name": package_name, "version": package_version or None}]
        else:
            return jsonify({"error": "Enter a package name or upload requirements.txt."}), 400

        if len(packages) > 30:
            return jsonify({"error": "For this demo, scan up to 30 package entries at a time."}), 400

        results = [scan_package(p["name"], p.get("version")) for p in packages]
        return jsonify({
            "results": results,
            "summary": {
                "scanned": len(results),
                "with_vulnerabilities": sum(1 for r in results if r["vulnerability_count"] > 0),
                "lookup_errors": sum(1 for r in results if r["status"] == "Lookup unavailable")
            }
        })
    except Exception as exc:
        # Avoid returning stack traces or secrets to the browser.
        app.logger.exception("Scan request failed")
        return jsonify({"error": "The scan could not be completed. Check your connection and try again."}), 500


@app.post("/api/source-check")
def api_source_check():
    """Run lightweight AST-based heuristics on a user-uploaded Python source file."""
    uploaded = request.files.get("source_file")
    if not uploaded or not uploaded.filename:
        return jsonify({"error": "Choose a .py source file first."}), 400
    if not uploaded.filename.lower().endswith(".py"):
        return jsonify({"error": "Only .py files are accepted."}), 400
    raw = uploaded.read()
    if len(raw) > 500_000:
        return jsonify({"error": "Source file must be 500 KB or smaller."}), 400
    result = scan_python_source(raw.decode("utf-8", errors="replace"))
    return jsonify(result)


@app.get("/api/analytics")
def api_analytics():
    return jsonify(get_demo_analytics())


if __name__ == "__main__":
    # Debug mode is disabled by default. Set FLASK_DEBUG=1 only for local development.
    debug_enabled = os.environ.get("FLASK_DEBUG", "0").strip().lower() in {"1", "true", "yes"}
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=debug_enabled)
