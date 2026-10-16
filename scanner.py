import ast
import re
import requests
from packaging.requirements import Requirement, InvalidRequirement

PYPI_JSON = "https://pypi.org/pypi/{name}/json"
OSV_QUERY = "https://api.osv.dev/v1/query"
HTTP_TIMEOUT = 8


def _clean_package_name(name):
    """Accept common PyPI names; reject paths, URLs and unexpected characters."""
    name = (name or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", name):
        raise ValueError("Invalid package name. Use a PyPI package name only.")
    return name


def parse_requirements(text):
    """Parse simple requirements.txt entries; ignore comments/options and unsupported lines."""
    parsed = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(("-", "--")):
            continue
        # Strip inline comments in common requirements format.
        line = line.split(" #", 1)[0].strip()
        try:
            req = Requirement(line)
            if req.url:
                continue  # Do not fetch arbitrary direct URLs.
            version = None
            # Use an exact == pin if present; otherwise OSV checks package metadata/latest.
            exact = [s.version for s in req.specifier if s.operator == "==" and "*" not in s.version]
            if exact:
                version = exact[0]
            parsed.append({"name": req.name, "version": version})
        except InvalidRequirement:
            continue
    # De-duplicate case-insensitively while preserving order.
    seen, output = set(), []
    for item in parsed:
        key = (item["name"].lower(), item["version"] or "")
        if key not in seen:
            seen.add(key)
            output.append(item)
    return output


def scan_package(name, version=None):
    """Query PyPI metadata and OSV vulnerability records. Network failure is reported honestly."""
    try:
        name = _clean_package_name(name)
    except ValueError as exc:
        return {
            "name": str(name), "version": version or "Not specified",
            "status": "Invalid input", "risk_level": "Unknown", "risk_score": None,
            "vulnerability_count": 0, "vulnerabilities": [], "metadata": {},
            "notes": [str(exc)]
        }

    metadata = {}
    notes = []
    chosen_version = version

    try:
        if version:
            pypi_url = f"https://pypi.org/pypi/{name}/{version}/json"
        else:
            pypi_url = PYPI_JSON.format(name=name)
        response = requests.get(pypi_url, timeout=HTTP_TIMEOUT)
        if response.status_code == 404:
            return {
                "name": name, "version": version or "Not found",
                "status": "Package not found", "risk_level": "Unknown", "risk_score": None,
                "vulnerability_count": 0, "vulnerabilities": [], "metadata": {},
                "notes": ["PyPI did not find this package/version. Check the spelling and version."]
            }
        response.raise_for_status()
        data = response.json()
        info = data.get("info", {})
        chosen_version = chosen_version or info.get("version") or "Unknown"
        metadata = {
            "summary": info.get("summary") or "No summary provided",
            "author": info.get("author") or "Not listed",
            "license": info.get("license") or "Not listed",
            "latest_version": info.get("version") or "Unknown",
            "requires_python": info.get("requires_python") or "Not specified",
            "project_url": info.get("project_url") or f"https://pypi.org/project/{name}/",
        }
    except requests.RequestException:
        notes.append("PyPI metadata could not be retrieved. Network access may be unavailable.")
        chosen_version = chosen_version or "Unknown"

    vulnerabilities = []
    osv_ok = False
    try:
        payload = {"package": {"name": name, "ecosystem": "PyPI"}}
        if chosen_version and chosen_version != "Unknown":
            payload["version"] = chosen_version
        response = requests.post(OSV_QUERY, json=payload, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        osv_data = response.json()
        osv_ok = True
        for vuln in osv_data.get("vulns", []):
            severity = "Unknown"
            # Prefer CVSS severity if OSV provides it; fall back to database severity.
            for sev in vuln.get("severity", []):
                if sev.get("score"):
                    severity = sev["score"]
                    break
            vulnerabilities.append({
                "id": vuln.get("id", "Unknown ID"),
                "summary": vuln.get("summary") or "No summary supplied by OSV",
                "modified": vuln.get("modified", "Unknown"),
                "severity": severity,
                "details_url": f"https://osv.dev/vulnerability/{vuln.get('id', '')}"
            })
    except requests.RequestException:
        notes.append("OSV vulnerability lookup failed. A failed lookup is not evidence that the package is safe.")

    if not osv_ok:
        status = "Lookup unavailable"
        risk_level, risk_score = "Unknown", None
    else:
        count = len(vulnerabilities)
        if count == 0:
            risk_level, risk_score = "No known findings", 0
            status = "No known vulnerabilities returned"
            notes.append("This result only reflects the OSV query; it does not prove the package is safe.")
        else:
            # Transparent demo score based on count only, not a validated security model.
            risk_score = min(100, count * 25)
            risk_level = "High" if count >= 3 else "Medium" if count >= 2 else "Review"
            status = "Vulnerabilities found"

    return {
        "name": name,
        "version": chosen_version or "Unknown",
        "status": status,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "vulnerability_count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
        "metadata": metadata,
        "notes": notes
    }


SUSPICIOUS_CALLS = {
    "eval": "Dynamic code evaluation (eval)",
    "exec": "Dynamic code execution (exec)",
    "subprocess.Popen": "Process creation (subprocess.Popen)",
    "os.system": "Shell command execution (os.system)",
    "socket.socket": "Network socket use (socket.socket)",
    "requests.get": "Outbound HTTP request (requests.get)",
    "urllib.request.urlopen": "Outbound URL request (urlopen)",
}


def scan_python_source(source):
    """AST heuristic only; reports patterns for human review, not a malware verdict."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return {"ok": False, "error": f"Python syntax error on line {exc.lineno}: {exc.msg}", "findings": []}

    findings = []
    imported_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_names.add(node.module)

    source_lines = source.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            label = None
            if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                label = SUSPICIOUS_CALLS[node.func.id]
            elif isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    dotted = f"{node.func.value.id}.{node.func.attr}"
                    label = SUSPICIOUS_CALLS.get(dotted)
            if label:
                findings.append({
                    "line": getattr(node, "lineno", "?"),
                    "pattern": label,
                    "snippet": source_lines[node.lineno - 1].strip()[:180] if getattr(node, "lineno", None) else ""
                })

    return {
        "ok": True,
        "imports": sorted(imported_names),
        "findings": findings,
        "finding_count": len(findings),
        "message": "Heuristic source review completed. These patterns can be legitimate; manual review is required."
    }
