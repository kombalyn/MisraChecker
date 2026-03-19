"""
MISRAChecker – main entry point.

Orchestrates language detection, rule loading, and violation collection.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union

from .models import CheckReport, Standard, Violation


# Language → standard mapping
_EXTENSION_STANDARD: Dict[str, Standard] = {
    ".c":   Standard.C2012,
    ".h":   Standard.C2012,
    ".cpp": Standard.CPP2023,
    ".cc":  Standard.CPP2023,
    ".cxx": Standard.CPP2023,
    ".hpp": Standard.CPP2023,
    ".hh":  Standard.CPP2023,
    ".py":  Standard.PY2024,
}


def _detect_standard(path: Path, override: Optional[Standard]) -> Optional[Standard]:
    if override:
        return override
    return _EXTENSION_STANDARD.get(path.suffix.lower())


class MISRAChecker:
    """
    Main MISRA compliance checker.

    Parameters
    ----------
    standard : Standard | None
        Force a specific standard; ``None`` = auto-detect from file extension.
    severity_filter : list[str] | None
        Only report violations at or above these severities.
        E.g. ``["mandatory", "required"]`` suppresses advisory.
    enabled_rules : list[str] | None
        Whitelist of rule IDs to enable. ``None`` = all rules.
    disabled_rules : list[str] | None
        Blacklist of rule IDs to skip.
    suppress_comments : bool
        Honour inline ``// MISRA-suppress: RULE_ID reason`` comments.
    """

    def __init__(
        self,
        standard: Optional[Standard] = None,
        severity_filter: Optional[List[str]] = None,
        enabled_rules:  Optional[List[str]] = None,
        disabled_rules: Optional[List[str]] = None,
        suppress_comments: bool = True,
    ) -> None:
        self.standard          = standard
        self.severity_filter   = set(severity_filter or [])
        self.enabled_rules     = set(enabled_rules  or [])
        self.disabled_rules    = set(disabled_rules or [])
        self.suppress_comments = suppress_comments

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_file(self, path: Union[str, Path]) -> CheckReport:
        """Check a single file and return a ``CheckReport``."""
        p = Path(path)
        std = _detect_standard(p, self.standard)
        report = CheckReport(standard=std or Standard.C2012, files=[str(p)])

        if not p.exists():
            report.errors.append(f"File not found: {p}")
            return report
        if std is None:
            report.errors.append(
                f"Unsupported file type '{p.suffix}' for {p} – "
                "expected .c/.h, .cpp/.hpp, or .py"
            )
            return report

        try:
            source = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            report.errors.append(f"Cannot read {p}: {exc}")
            return report

        violations = self._analyse(source, str(p), std)
        report.violations = self._apply_filters(violations, source)
        return report

    def check_string(
        self,
        source: str,
        filename: str = "<string>",
        standard: Optional[Standard] = None,
    ) -> CheckReport:
        """Check source code supplied as a string (useful for agent integration)."""
        std = standard or self.standard
        if std is None:
            # guess from filename
            std = _detect_standard(Path(filename), None) or Standard.C2012

        report = CheckReport(standard=std, files=[filename])
        violations = self._analyse(source, filename, std)
        report.violations = self._apply_filters(violations, source)
        return report

    def check_directory(
        self,
        directory: Union[str, Path],
        recursive: bool = True,
        extensions: Optional[List[str]] = None,
    ) -> CheckReport:
        """Recursively check all supported source files in *directory*."""
        base = Path(directory)
        exts = set(extensions) if extensions else set(_EXTENSION_STANDARD.keys())

        std = self.standard or Standard.C2012   # aggregate report uses forced std or C
        report = CheckReport(standard=std, files=[])

        glob = base.rglob("*") if recursive else base.glob("*")
        for path in sorted(glob):
            if path.is_file() and path.suffix.lower() in exts:
                sub = self.check_file(path)
                report.files.append(str(path))
                report.violations.extend(sub.violations)
                report.errors.extend(sub.errors)
        return report

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _analyse(self, source: str, filename: str, std: Standard) -> List[Violation]:
        """Dispatch to the correct language analyser."""
        if std == Standard.C2012:
            from .languages.c_analyser import CAnalyser
            return CAnalyser().analyse(source, filename)
        if std == Standard.CPP2023:
            from .languages.cpp_analyser import CppAnalyser
            return CppAnalyser().analyse(source, filename)
        if std == Standard.PY2024:
            from .languages.python_analyser import PythonAnalyser
            return PythonAnalyser().analyse(source, filename)
        return []

    def _apply_filters(self, violations: List[Violation], source: str) -> List[Violation]:
        """Apply rule filters and inline suppression markers."""
        suppressed_lines = _collect_suppressions(source) if self.suppress_comments else {}
        result = []
        for v in violations:
            # Rule whitelist / blacklist
            if self.enabled_rules and v.rule_id not in self.enabled_rules:
                continue
            if v.rule_id in self.disabled_rules:
                continue
            # Severity filter
            if self.severity_filter and v.severity.value not in self.severity_filter:
                continue
            # Inline suppression
            if v.rule_id in suppressed_lines.get(v.line, set()):
                v.suppressed = True
            result.append(v)
        return result


# ------------------------------------------------------------------
# Inline suppression parser
# ------------------------------------------------------------------

def _collect_suppressions(source: str) -> Dict[int, set]:
    """
    Parse inline suppression comments:
        C/C++:  // MISRA-suppress: C2012-14.4 intentional goto
        Python: # MISRA-suppress: PY2024-1.2 legacy code

    Returns {line_number: {rule_id, ...}}
    """
    import re
    pattern = re.compile(r"MISRA-suppress:\s*([\w.\-]+)")
    result: Dict[int, set] = {}
    for lineno, line in enumerate(source.splitlines(), start=1):
        for m in pattern.finditer(line):
            result.setdefault(lineno, set()).add(m.group(1))
    return result
