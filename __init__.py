"""
MISRA Compliance Checker
========================
Static analysis tool for MISRA C:2012, MISRA C++:2023, and MISRA Python:2024.

Usage:
    from misra_checker import MISRAChecker, Standard
    checker = MISRAChecker(standard=Standard.C2012)
    report = checker.check_file("main.c")
    print(report.summary())
"""

from .checker import MISRAChecker
from .models import (
    Standard,
    Severity,
    Violation,
    CheckReport,
    RuleCategory,
)

__version__ = "1.0.0"
__all__ = [
    "MISRAChecker",
    "Standard",
    "Severity",
    "Violation",
    "CheckReport",
    "RuleCategory",
]
