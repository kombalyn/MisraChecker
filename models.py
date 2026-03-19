"""
Core data models for MISRA compliance checking.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional


class Standard(str, Enum):
    """Supported MISRA standards."""
    C2012    = "MISRA_C_2012"
    CPP2023  = "MISRA_CPP_2023"
    PY2024   = "MISRA_PY_2024"


class Severity(str, Enum):
    """Violation severity levels (maps to MISRA mandatory/required/advisory)."""
    MANDATORY = "mandatory"   # Must be fixed – no deviation permitted
    REQUIRED  = "required"    # Must be fixed or formally deviated
    ADVISORY  = "advisory"    # Should be fixed; deviation easier to justify
    INFO      = "info"        # Non-MISRA informational note


class RuleCategory(str, Enum):
    """High-level rule categories."""
    # Shared
    LANGUAGE_EXTENSIONS   = "language_extensions"
    PREPROCESSING         = "preprocessing"
    DECLARATIONS          = "declarations"
    EXPRESSIONS           = "expressions"
    CONTROL_FLOW          = "control_flow"
    FUNCTIONS             = "functions"
    POINTERS_ARRAYS       = "pointers_arrays"
    TYPES                 = "types"
    CONVERSIONS           = "conversions"
    IDENTIFIERS           = "identifiers"
    MEMORY                = "memory"
    ERROR_HANDLING        = "error_handling"
    # Python-specific
    IMPORTS               = "imports"
    EXCEPTIONS            = "exceptions"
    NAMING_CONVENTIONS    = "naming_conventions"
    COMPLEXITY            = "complexity"


@dataclass
class RuleSpec:
    """Metadata for a single MISRA rule."""
    rule_id:     str            # e.g. "C2012-15.1", "CPP2023-6.4.1", "PY2024-3.1"
    standard:    Standard
    category:    RuleCategory
    severity:    Severity
    title:       str
    description: str
    rationale:   str = ""
    example_bad: str = ""
    example_good: str = ""


@dataclass
class Violation:
    """A single detected MISRA rule violation."""
    rule:        RuleSpec
    file_path:   str
    line:        int
    column:      int = 0
    snippet:     str = ""
    message:     str = ""
    suppressed:  bool = False

    @property
    def rule_id(self) -> str:
        return self.rule.rule_id

    @property
    def severity(self) -> Severity:
        return self.rule.severity

    def to_dict(self) -> dict:
        return {
            "rule_id":   self.rule_id,
            "standard":  self.rule.standard.value,
            "severity":  self.severity.value,
            "category":  self.rule.category.value,
            "title":     self.rule.title,
            "file":      self.file_path,
            "line":      self.line,
            "column":    self.column,
            "snippet":   self.snippet,
            "message":   self.message,
            "suppressed": self.suppressed,
        }

    def __str__(self) -> str:
        loc = f"{self.file_path}:{self.line}"
        if self.column:
            loc += f":{self.column}"
        flag = " [SUPPRESSED]" if self.suppressed else ""
        return (
            f"[{self.severity.value.upper()}] {self.rule_id} "
            f"({self.rule.title}) @ {loc}{flag}\n"
            f"  {self.message or self.snippet}"
        )


@dataclass
class CheckReport:
    """Full compliance report for one or more files."""
    standard:    Standard
    files:       List[str] = field(default_factory=list)
    violations:  List[Violation] = field(default_factory=list)
    errors:      List[str] = field(default_factory=list)   # parse errors / skipped files

    # ------------------------------------------------------------------ counts
    @property
    def mandatory_count(self) -> int:
        return sum(1 for v in self.violations if not v.suppressed and v.severity == Severity.MANDATORY)

    @property
    def required_count(self) -> int:
        return sum(1 for v in self.violations if not v.suppressed and v.severity == Severity.REQUIRED)

    @property
    def advisory_count(self) -> int:
        return sum(1 for v in self.violations if not v.suppressed and v.severity == Severity.ADVISORY)

    @property
    def active_violations(self) -> List[Violation]:
        return [v for v in self.violations if not v.suppressed]

    @property
    def is_compliant(self) -> bool:
        """True only when there are zero mandatory or required violations."""
        return self.mandatory_count == 0 and self.required_count == 0

    # ---------------------------------------------------------------- output
    def summary(self) -> str:
        lines = [
            f"MISRA Compliance Report – {self.standard.value}",
            "=" * 55,
            f"Files checked : {len(self.files)}",
            f"Violations    : {len(self.active_violations)} "
            f"(mandatory={self.mandatory_count}, "
            f"required={self.required_count}, "
            f"advisory={self.advisory_count})",
            f"Parse errors  : {len(self.errors)}",
            f"Status        : {'COMPLIANT ✓' if self.is_compliant else 'NON-COMPLIANT ✗'}",
            "",
        ]
        if self.active_violations:
            lines.append("Violations:")
            lines.append("-" * 55)
            for v in self.active_violations:
                lines.append(str(v))
        if self.errors:
            lines.append("\nParse / IO errors:")
            lines.extend(f"  ! {e}" for e in self.errors)
        return "\n".join(lines)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            {
                "standard":   self.standard.value,
                "files":      self.files,
                "compliant":  self.is_compliant,
                "counts": {
                    "mandatory": self.mandatory_count,
                    "required":  self.required_count,
                    "advisory":  self.advisory_count,
                    "total":     len(self.active_violations),
                },
                "violations": [v.to_dict() for v in self.violations],
                "errors":     self.errors,
            },
            indent=indent,
            ensure_ascii=False,
        )

    def to_sarif(self) -> dict:
        """
        Basic SARIF 2.1.0 output for GitHub Code Scanning / IDE integration.
        """
        rules = {}
        results = []
        for v in self.active_violations:
            rid = v.rule_id
            if rid not in rules:
                rules[rid] = {
                    "id": rid,
                    "name": v.rule.title,
                    "shortDescription": {"text": v.rule.title},
                    "fullDescription":  {"text": v.rule.description},
                    "defaultConfiguration": {
                        "level": {
                            Severity.MANDATORY: "error",
                            Severity.REQUIRED:  "warning",
                            Severity.ADVISORY:  "note",
                            Severity.INFO:      "none",
                        }.get(v.severity, "warning")
                    },
                    "properties": {"tags": [self.standard.value, v.rule.category.value]},
                }
            results.append({
                "ruleId": rid,
                "level": rules[rid]["defaultConfiguration"]["level"],
                "message": {"text": v.message or v.snippet},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": v.file_path},
                        "region": {
                            "startLine": v.line,
                            "startColumn": v.column or 1,
                        },
                    }
                }],
            })
        return {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "misra-checker",
                        "version": "1.0.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }],
        }
