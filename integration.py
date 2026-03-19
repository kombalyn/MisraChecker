"""
Integration adapters for the Programozó Ágens project.

Provides:
  1. LangChain tool  – callable from programozo_agent.py
  2. Flask blueprint – mountable on agent_server.py
  3. Standalone function – usable from any Python code
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# 1.  Standalone helper
# ---------------------------------------------------------------------------

def check_code(
    source: str,
    filename: str = "<string>",
    standard: Optional[str] = None,
) -> dict:
    """
    Check *source* for MISRA compliance and return a result dict.

    Parameters
    ----------
    source   : source code as a string
    filename : used for language detection (e.g. "main.c", "app.py")
    standard : e.g. "MISRA_C_2012" – overrides auto-detection

    Returns
    -------
    {
        "compliant": bool,
        "counts": {"mandatory": int, "required": int, "advisory": int, "total": int},
        "violations": [...],
        "summary": str,
    }
    """
    from misra_checker import MISRAChecker, Standard

    std = Standard(standard) if standard else None
    checker = MISRAChecker(standard=std)
    report = checker.check_string(source, filename=filename)
    return {
        "compliant":  report.is_compliant,
        "counts": {
            "mandatory": report.mandatory_count,
            "required":  report.required_count,
            "advisory":  report.advisory_count,
            "total":     len(report.active_violations),
        },
        "violations": [v.to_dict() for v in report.active_violations],
        "summary":    report.summary(),
    }


# ---------------------------------------------------------------------------
# 2.  LangChain tool
# ---------------------------------------------------------------------------

def make_langchain_tool():
    """
    Returns a LangChain @tool compatible with programozo_agent.py.

    Usage in programozo_agent.py:
        from misra_checker.integration import make_langchain_tool
        tools.append(make_langchain_tool())
    """
    try:
        from langchain_core.tools import tool

        @tool
        def check_misra_compliance(file_path: str) -> str:
            """
            Checks a source file for MISRA compliance (C:2012, C++:2023, Python:2024).
            file_path: path to the .c, .h, .cpp, .hpp, or .py file to check.
            Returns a human-readable compliance report.
            """
            p = Path(file_path)
            if not p.exists():
                return f"File not found: {file_path}"
            from misra_checker import MISRAChecker
            checker = MISRAChecker()
            report = checker.check_file(p)
            return report.summary()

        return check_misra_compliance
    except ImportError:
        raise ImportError(
            "LangChain is not installed. "
            "Install it with: pip install langchain-core"
        )


# ---------------------------------------------------------------------------
# 3.  Flask blueprint
# ---------------------------------------------------------------------------

def make_flask_blueprint():
    """
    Returns a Flask Blueprint that can be registered on agent_server.py.

    Usage in agent_server.py:
        from misra_checker.integration import make_flask_blueprint
        app.register_blueprint(make_flask_blueprint(), url_prefix="/misra")

    Endpoints:
        POST /misra/check      – Body: {"code": "...", "filename": "main.c"}
        POST /misra/check-file – Body: {"path": "output/main.c"}
        GET  /misra/rules      – List all rules (optional ?standard=MISRA_C_2012)
    """
    try:
        from flask import Blueprint, jsonify, request
    except ImportError:
        raise ImportError("Flask is not installed. Install with: pip install flask")

    bp = Blueprint("misra", __name__)

    @bp.route("/check", methods=["POST"])
    def check():
        data = request.get_json(silent=True) or {}
        code     = data.get("code", "").strip()
        filename = data.get("filename", "<string>")
        standard = data.get("standard")

        if not code:
            return jsonify({"error": "Missing 'code' field"}), 400

        result = check_code(code, filename=filename, standard=standard)
        return jsonify(result), 200

    @bp.route("/check-file", methods=["POST"])
    def check_file_endpoint():
        data = request.get_json(silent=True) or {}
        path = data.get("path", "").strip()
        if not path:
            return jsonify({"error": "Missing 'path' field"}), 400

        p = Path(path)
        if not p.exists():
            return jsonify({"error": f"File not found: {path}"}), 404

        from misra_checker import MISRAChecker
        checker = MISRAChecker()
        report  = checker.check_file(p)
        return jsonify(json.loads(report.to_json())), 200

    @bp.route("/rules", methods=["GET"])
    def list_rules():
        from misra_checker import Standard
        from misra_checker.rules.registry import get_registry, get_rules_for_standard

        std_str = request.args.get("standard")
        if std_str:
            try:
                rules = get_rules_for_standard(Standard(std_str))
            except ValueError:
                return jsonify({"error": f"Unknown standard: {std_str}"}), 400
        else:
            rules = list(get_registry().values())

        return jsonify([
            {
                "rule_id":     r.rule_id,
                "standard":    r.standard.value,
                "severity":    r.severity.value,
                "category":    r.category.value,
                "title":       r.title,
                "description": r.description,
                "rationale":   r.rationale,
            }
            for r in sorted(rules, key=lambda r: r.rule_id)
        ]), 200

    return bp
