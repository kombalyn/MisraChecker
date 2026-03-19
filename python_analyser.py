"""
MISRA Python:2024 analyser.

Uses Python's built-in ``ast`` module for accurate structural analysis,
combined with regex line-scans for pattern-based rules.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Set, Tuple

from ..models import Violation
from .base import BaseAnalyser


class PythonAnalyser(BaseAnalyser):
    """MISRA Python:2024 static analyser."""

    def _run_checks(self) -> List[Violation]:
        violations: List[Violation] = []
        tree: Optional[ast.Module] = None
        try:
            tree = ast.parse(self._source, filename=self._filename)
        except SyntaxError as exc:
            # Syntax errors are reported via CheckReport.errors
            violations.append(self._syntax_error_violation(exc))
            return violations

        # AST-based checks
        visitor = _MISRAVisitor(self._filename, self._lines)
        visitor.visit(tree)
        violations.extend(visitor.violations)

        # Line-based checks (faster for simple patterns)
        self._check_wildcard_import(violations)
        self._check_none_comparison(violations)
        self._check_bool_comparison(violations)
        self._check_eval_exec(violations)
        self._check_global_statement(violations)
        self._check_assert_statement(violations)
        self._check_dunder_import(violations)
        self._check_continue_statement(violations)
        self._check_not_in_operator(violations)
        self._check_duplicate_imports(violations)
        return violations

    def _syntax_error_violation(self, exc: SyntaxError) -> Violation:
        from ..rules.registry import get_rule
        from ..models import RuleSpec, RuleCategory, Severity, Standard
        rule = RuleSpec(
            rule_id="PY2024-SYNTAX",
            standard=Standard.PY2024,
            category=RuleCategory.LANGUAGE_EXTENSIONS,
            severity=Severity.MANDATORY,
            title="Syntax error",
            description=str(exc),
        )
        return Violation(rule=rule, file_path=self._filename,
                         line=exc.lineno or 1, message=str(exc))

    # ----------------------------------------------------------------
    # Regex-based line checks
    # ----------------------------------------------------------------

    def _check_wildcard_import(self, v: List[Violation]) -> None:
        """PY2024-1.1"""
        pat = re.compile(r'^\s*from\s+\S+\s+import\s+\*')
        for lineno, line in enumerate(self._lines, 1):
            if pat.match(line):
                self._add(v, "PY2024-1.1", lineno,
                          message="Wildcard import 'from X import *' is prohibited")

    def _check_none_comparison(self, v: List[Violation]) -> None:
        """PY2024-3.1"""
        pat = re.compile(r'(?:==|!=)\s*None|None\s*(?:==|!=)')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if pat.search(line):
                self._add(v, "PY2024-3.1", lineno,
                          message="Use 'is None' / 'is not None' instead of '== None' / '!= None'")

    def _check_bool_comparison(self, v: List[Violation]) -> None:
        """PY2024-3.2"""
        pat = re.compile(r'(?:==|!=)\s*(?:True|False)|(?:True|False)\s*(?:==|!=)')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if pat.search(line):
                self._add(v, "PY2024-3.2", lineno,
                          message="Compare to True/False with 'is' or use direct boolean test")

    def _check_eval_exec(self, v: List[Violation]) -> None:
        """PY2024-8.1"""
        pat = re.compile(r'\b(eval|exec)\s*\(')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            m = pat.search(line)
            if m:
                self._add(v, "PY2024-8.1", lineno,
                          message=f"'{m.group(1)}()' executes dynamic code and is prohibited")

    def _check_global_statement(self, v: List[Violation]) -> None:
        """PY2024-8.2"""
        pat = re.compile(r'^\s*global\b')
        for lineno, line in enumerate(self._lines, 1):
            if pat.match(line):
                self._add(v, "PY2024-8.2", lineno,
                          message="'global' statement modifies module-level state from within a function")

    def _check_assert_statement(self, v: List[Violation]) -> None:
        """PY2024-8.3"""
        pat = re.compile(r'^\s*assert\b')
        for lineno, line in enumerate(self._lines, 1):
            if pat.match(line):
                self._add(v, "PY2024-8.3", lineno,
                          message="'assert' can be disabled with -O; use explicit if/raise for production checks")

    def _check_dunder_import(self, v: List[Violation]) -> None:
        """PY2024-8.4"""
        pat = re.compile(r'\b__import__\s*\(')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if pat.search(line):
                self._add(v, "PY2024-8.4", lineno,
                          message="__import__() is prohibited; use importlib.import_module() instead")

    def _check_continue_statement(self, v: List[Violation]) -> None:
        """PY2024-4.3"""
        pat = re.compile(r'^\s*continue\b')
        for lineno, line in enumerate(self._lines, 1):
            if pat.match(line) and not _in_comment(line):
                self._add(v, "PY2024-4.3", lineno,
                          message="'continue' statement makes loop logic harder to follow")

    def _check_not_in_operator(self, v: List[Violation]) -> None:
        """PY2024-3.3 – use 'not in' / 'is not' compound operators."""
        pat = re.compile(r'\bnot\s+\w+\s+in\b|\bnot\s+\w+\s+is\b')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if pat.search(line):
                self._add(v, "PY2024-3.3", lineno,
                          message="Use 'not in' / 'is not' compound operators instead of 'not x in' / 'not x is'")

    def _check_duplicate_imports(self, v: List[Violation]) -> None:
        """PY2024-1.3"""
        seen: Dict[str, int] = {}
        imp = re.compile(r'^\s*import\s+([\w.]+)|^\s*from\s+([\w.]+)\s+import')
        for lineno, line in enumerate(self._lines, 1):
            m = imp.match(line)
            if m:
                mod = m.group(1) or m.group(2)
                if mod in seen:
                    self._add(v, "PY2024-1.3", lineno,
                              message=f"Module '{mod}' imported more than once (first at line {seen[mod]})")
                else:
                    seen[mod] = lineno


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------

class _MISRAVisitor(ast.NodeVisitor):
    """
    Single-pass AST visitor that collects MISRA Python:2024 violations.
    """

    def __init__(self, filename: str, lines: List[str]) -> None:
        self.filename   = filename
        self.lines      = lines
        self.violations: List[Violation] = []
        self._func_stack: List[ast.FunctionDef] = []
        self._class_names: Set[str] = set()

    # ---------------------------------------------------------------- helpers

    def _add(self, rule_id: str, node: ast.AST, message: str = "") -> None:
        from ..rules.registry import get_rule
        rule = get_rule(rule_id)
        if rule is None:
            return
        lineno = getattr(node, "lineno", 1)
        col    = getattr(node, "col_offset", 0)
        snippet = self.lines[lineno - 1].strip() if 0 < lineno <= len(self.lines) else ""
        self.violations.append(Violation(
            rule=rule, file_path=self.filename,
            line=lineno, column=col,
            snippet=snippet[:120],
            message=message or rule.description,
        ))

    # ---------------------------------------------------------------- visitors

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # PY2024-1.1 handled by regex; no AST check needed
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._func_stack.append(node)
        self._check_type_annotations(node)
        self._check_mutable_defaults(node)
        self._check_recursion(node)
        self._check_function_length(node)
        self._check_param_count(node)
        self._check_multiple_returns(node)
        self._check_if_elif_else(node)
        self.generic_visit(node)
        self._func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """PY2024-2.2 – class names shall be PascalCase."""
        self._class_names.add(node.name)
        if not _is_pascal_case(node.name):
            self._add("PY2024-2.2", node,
                      f"Class '{node.name}' should use CapWords (PascalCase) naming")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        """PY2024-2.3 – variable names should be snake_case."""
        if isinstance(node.ctx, ast.Store):
            if not _is_snake_case_or_const(node.id) and not _is_pascal_case(node.id):
                if len(node.id) > 1 and node.id not in self._class_names:
                    pass  # Too noisy without scope tracking; skip
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """PY2024-6.1 bare except / PY2024-6.3 empty except."""
        if node.type is None:
            self._add("PY2024-6.1", node, "Bare 'except:' catches all exceptions including SystemExit")
        # PY2024-6.3: empty body (only Pass / Ellipsis)
        body = node.body
        if all(isinstance(s, (ast.Pass, ast.Expr)) and
               (not isinstance(s, ast.Expr) or isinstance(s.value, ast.Constant))
               for s in body):
            self._add("PY2024-6.3", node, "Empty except block silently suppresses exceptions")
        # PY2024-6.4: exception type should derive from Exception
        if node.type and isinstance(node.type, ast.Name):
            if node.type.id == "BaseException":
                self._add("PY2024-6.4", node,
                          "Catching BaseException is too broad; catch Exception instead")
        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> None:
        """PY2024-6.4 – raised exceptions should inherit from Exception."""
        if node.exc and isinstance(node.exc, ast.Call):
            name = _call_name(node.exc)
            if name == "BaseException":
                self._add("PY2024-6.4", node,
                          "Raise Exception (or subclass), not BaseException")
        self.generic_visit(node)

    # ---------------------------------------------------------------- helpers

    def _check_type_annotations(self, node: ast.FunctionDef) -> None:
        """PY2024-5.1"""
        args = node.args
        all_args = args.args + args.posonlyargs + args.kwonlyargs
        if args.vararg:
            all_args.append(args.vararg)
        if args.kwarg:
            all_args.append(args.kwarg)

        missing: List[str] = []
        for arg in all_args:
            if arg.arg == "self" or arg.arg == "cls":
                continue
            if arg.annotation is None:
                missing.append(arg.arg)
        if missing:
            self._add("PY2024-5.1", node,
                      f"Missing type annotations for parameter(s): {', '.join(missing)}")
        if node.returns is None and node.name != "__init__":
            self._add("PY2024-5.1", node,
                      f"Function '{node.name}' is missing a return type annotation")

    def _check_mutable_defaults(self, node: ast.FunctionDef) -> None:
        """PY2024-5.2"""
        for default in node.args.defaults + node.args.kw_defaults:
            if default is None:
                continue
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self._add("PY2024-5.2", node,
                          f"Mutable default argument in '{node.name}' – use None and initialise inside function")

    def _check_recursion(self, node: ast.FunctionDef) -> None:
        """PY2024-5.3"""
        fname = node.name
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                if child.func.id == fname and child is not node:
                    self._add("PY2024-5.3", child,
                              f"Function '{fname}' calls itself recursively")
                    break

    def _check_function_length(self, node: ast.FunctionDef) -> None:
        """PY2024-5.4"""
        start = node.lineno
        end   = node.end_lineno or node.lineno
        if (end - start) > 50:
            self._add("PY2024-5.4", node,
                      f"Function '{node.name}' is {end - start} lines (limit: 50)")

    def _check_param_count(self, node: ast.FunctionDef) -> None:
        """PY2024-5.5"""
        args = node.args
        params = [a for a in args.args if a.arg not in ("self", "cls")]
        params += args.kwonlyargs
        if len(params) > 5:
            self._add("PY2024-5.5", node,
                      f"Function '{node.name}' has {len(params)} parameters (limit: 5)")

    def _check_multiple_returns(self, node: ast.FunctionDef) -> None:
        """PY2024-4.2"""
        returns = [n for n in ast.walk(node) if isinstance(n, ast.Return)]
        if len(returns) > 1:
            for ret in returns[1:]:
                self._add("PY2024-4.2", ret,
                          f"Function '{node.name}' has multiple return statements")

    def _check_if_elif_else(self, node: ast.FunctionDef) -> None:
        """PY2024-4.1 – if/elif chains should end with else."""
        for child in ast.walk(node):
            if isinstance(child, ast.If):
                # Check if this is an elif chain
                if child.orelse and isinstance(child.orelse[0], ast.If):
                    # It's an elif – recurse to check if it ends with plain else
                    tail = child
                    while tail.orelse and isinstance(tail.orelse[0], ast.If):
                        tail = tail.orelse[0]
                    if not tail.orelse:
                        self._add("PY2024-4.1", child,
                                  "if/elif chain is not terminated with a final else clause")


# ---------------------------------------------------------------------------
# Naming convention helpers
# ---------------------------------------------------------------------------

def _is_pascal_case(name: str) -> bool:
    return bool(re.match(r'^[A-Z][A-Za-z0-9]*$', name))


def _is_snake_case_or_const(name: str) -> bool:
    # snake_case or UPPER_CASE
    return bool(re.match(r'^[a-z_][a-z0-9_]*$', name) or re.match(r'^[A-Z_][A-Z0-9_]*$', name))


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _in_comment(line: str) -> bool:
    return line.lstrip().startswith('#')
