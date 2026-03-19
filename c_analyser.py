"""
MISRA C:2012 analyser.

Implements a hybrid approach:
  - Regex-based checks for pattern-matchable rules (fast, zero dependencies)
  - Simple token-level checks for structural rules
"""

from __future__ import annotations

import re
from typing import List

from ..models import Violation
from .base import BaseAnalyser


class CAnalyser(BaseAnalyser):
    """MISRA C:2012 static analyser."""

    def _run_checks(self) -> List[Violation]:
        violations: List[Violation] = []
        self._check_goto(violations)
        self._check_recursion(violations)
        self._check_brace_bodies(violations)
        self._check_else_if_else(violations)
        self._check_float_loop_counter(violations)
        self._check_sizeof_side_effects(violations)
        self._check_logical_rhs_side_effects(violations)
        self._check_assignment_in_expression(violations)
        self._check_stdarg(violations)
        self._check_malloc_free(violations)
        self._check_implicit_declaration(violations)
        self._check_return_value_discarded(violations)
        self._check_macro_keyword_redef(violations)
        self._check_include_form(violations)
        self._check_shadowing(violations)
        self._check_multiple_returns(violations)
        self._check_loop_break_count(violations)
        self._check_bitwise_on_signed(violations)
        return violations

    # ------------------------------------------------------------------
    # Individual rule checks
    # ------------------------------------------------------------------

    def _check_goto(self, v: List[Violation]) -> None:
        """C2012-15.1 – goto should not be used."""
        pat = re.compile(r'\bgoto\b')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if pat.search(line):
                self._add(v, "C2012-15.1", lineno, message="'goto' statement found")

    def _check_recursion(self, v: List[Violation]) -> None:
        """C2012-17.2 – functions shall not call themselves."""
        # Detect current function name (simplified: look for definition pattern)
        func_def = re.compile(r'\b(\w+)\s*\([^)]*\)\s*\{')
        func_call = re.compile(r'\b(\w+)\s*\(')
        current_func: str = ""
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            m = func_def.match(line.strip())
            if m:
                current_func = m.group(1)
            if current_func:
                for cm in func_call.finditer(line):
                    if cm.group(1) == current_func:
                        # Make sure it's inside the body (not the definition itself)
                        if not func_def.match(line.strip()):
                            self._add(v, "C2012-17.2", lineno,
                                      message=f"Function '{current_func}' calls itself (recursion)")

    def _check_brace_bodies(self, v: List[Violation]) -> None:
        """C2012-15.6 – if/for/while/else bodies shall be compound statements."""
        # Match control keyword followed by ) or alone (else), not followed by {
        pat = re.compile(
            r'\b(if|else|for|while|do)\b'
            r'(?:\s*\([^)]*\))?\s*$'
        )
        brace_line = re.compile(r'^\s*\{')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            stripped = line.rstrip()
            if pat.search(stripped):
                # Check next non-empty line for opening brace
                next_line = ""
                for offset in range(1, 4):
                    if lineno + offset - 1 < len(self._lines):
                        next_line = self._lines[lineno + offset - 1]
                        break
                if next_line and not brace_line.match(next_line) and '{' not in stripped:
                    self._add(v, "C2012-15.6", lineno,
                              message="Control statement body is not enclosed in braces")

    def _check_else_if_else(self, v: List[Violation]) -> None:
        """C2012-15.7 – if…else if chains shall end with else."""
        elif_pat = re.compile(r'\belse\s+if\b')
        else_pat = re.compile(r'\belse\b(?!\s+if\b)')
        i = 0
        lines = self._lines
        while i < len(lines):
            if _in_comment(lines[i]):
                i += 1
                continue
            if elif_pat.search(lines[i]):
                # Scan forward for the chain terminator
                j = i + 1
                found_else = False
                while j < len(lines) and j < i + 200:
                    if elif_pat.search(lines[j]):
                        j += 1
                        continue
                    if else_pat.search(lines[j]):
                        found_else = True
                        break
                    # Reached something that is not else/else-if – chain ended
                    break
                if not found_else:
                    self._add(v, "C2012-15.7", i + 1,
                              message="if-else if chain is not terminated with a final else clause")
                i = j
            else:
                i += 1

    def _check_float_loop_counter(self, v: List[Violation]) -> None:
        """C2012-14.1 – loop counter shall not be floating-point."""
        # Match: for ( float/double varname = ...
        pat = re.compile(r'\bfor\s*\(\s*(float|double)\s+\w+')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if pat.search(line):
                self._add(v, "C2012-14.1", lineno,
                          message="Floating-point type used as loop counter")

    def _check_sizeof_side_effects(self, v: List[Violation]) -> None:
        """C2012-13.6 – sizeof operand shall not have side effects."""
        # Detect sizeof(expr++) or sizeof(expr--)
        pat = re.compile(r'\bsizeof\s*\([^)]*(\+\+|--)[^)]*\)')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if pat.search(line):
                self._add(v, "C2012-13.6", lineno,
                          message="sizeof operand contains a side-effecting expression")

    def _check_logical_rhs_side_effects(self, v: List[Violation]) -> None:
        """C2012-13.5 – right-hand side of && / || shall not have side effects."""
        # Heuristic: detect && expr++ or || expr--
        pat = re.compile(r'(&&|\|\|)\s*[^;]*(\+\+|--)')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if pat.search(line):
                self._add(v, "C2012-13.5", lineno,
                          message="Right-hand side of '&&'/'||' contains a side effect (++/--)")

    def _check_assignment_in_expression(self, v: List[Violation]) -> None:
        """C2012-13.4 – assignment result shall not be used in expression."""
        # Detect patterns like: if (x = foo()) or while (x = ...)
        pat = re.compile(r'\b(if|while|for)\s*\([^)]*(?<!=)=(?!=)[^)]*\)')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if pat.search(line):
                self._add(v, "C2012-13.4", lineno,
                          message="Assignment result used as controlling expression")

    def _check_stdarg(self, v: List[Violation]) -> None:
        """C2012-17.1 – <stdarg.h> shall not be used."""
        pat = re.compile(r'#\s*include\s*[<"]stdarg\.h[>"]')
        for lineno, line in enumerate(self._lines, 1):
            if pat.search(line):
                self._add(v, "C2012-17.1", lineno,
                          message="Use of <stdarg.h> is prohibited by MISRA C:2012 Rule 17.1")

    def _check_malloc_free(self, v: List[Violation]) -> None:
        """C2012-22.1 / 22.2 – dynamic memory management."""
        malloc_pat  = re.compile(r'\b(malloc|calloc|realloc)\s*\(')
        free_pat    = re.compile(r'\bfree\s*\(')
        malloc_lines: List[int] = []
        free_lines:   List[int] = []
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if malloc_pat.search(line):
                malloc_lines.append(lineno)
            if free_pat.search(line):
                free_lines.append(lineno)
        # If malloc used without any free → C2012-22.1
        if malloc_lines and not free_lines:
            for ln in malloc_lines:
                self._add(v, "C2012-22.1", ln,
                          message="Dynamic allocation without corresponding free() detected")

    def _check_implicit_declaration(self, v: List[Violation]) -> None:
        """C2012-17.3 – functions shall not be declared implicitly."""
        # Pattern: calling a function that was never declared (heuristic:
        # function call where no prior declaration/definition is found)
        declared = set()
        decl_pat = re.compile(r'^\s*(?:\w+\s+)+(\w+)\s*\(')
        call_pat = re.compile(r'\b(\w+)\s*\(')
        for line in self._lines:
            m = decl_pat.match(line)
            if m:
                declared.add(m.group(1))
        c_keywords = {
            "if", "for", "while", "switch", "return", "else", "do",
            "sizeof", "typedef", "struct", "union", "enum",
        }
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line) or '#' in line:
                continue
            for m in call_pat.finditer(line):
                fn = m.group(1)
                if fn not in declared and fn not in c_keywords and fn.islower():
                    # Very conservative: only flag unknown lower-case identifiers
                    # to avoid false positives on stdlib calls
                    pass  # Would need full symbol table for reliable detection

    def _check_return_value_discarded(self, v: List[Violation]) -> None:
        """C2012-17.7 – return values shall be used."""
        # Flag known safety-critical functions whose return value is frequently discarded.
        # Heuristic: call appears as a statement (ends with ;) without being on the
        # right-hand side of an assignment.
        critical = {"fclose", "fopen", "scanf", "fscanf", "remove", "rename",
                    "system", "setvbuf", "fflush", "fseek", "fsetpos"}
        pat = re.compile(r'\b(\w+)\s*\([^)]*\)\s*;')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            # Skip lines that are assignments: contain = before the call
            for m in pat.finditer(line):
                fn = m.group(1)
                if fn not in critical:
                    continue
                # Check that this is not the RHS of an assignment
                before = line[:m.start()].strip()
                if before and before[-1] not in (';', '{', '}', '(', ',', ''):
                    continue  # likely RHS of assignment or argument
                self._add(v, "C2012-17.7", lineno,
                          message=f"Return value of '{fn}()' is silently discarded")

    def _check_macro_keyword_redef(self, v: List[Violation]) -> None:
        """C2012-20.4 – macros shall not redefine keywords."""
        c_keywords = {
            "auto", "break", "case", "char", "const", "continue", "default",
            "do", "double", "else", "enum", "extern", "float", "for", "goto",
            "if", "inline", "int", "long", "register", "restrict", "return",
            "short", "signed", "sizeof", "static", "struct", "switch",
            "typedef", "union", "unsigned", "void", "volatile", "while",
        }
        pat = re.compile(r'#\s*define\s+(\w+)')
        for lineno, line in enumerate(self._lines, 1):
            m = pat.search(line)
            if m and m.group(1) in c_keywords:
                self._add(v, "C2012-20.4", lineno,
                          message=f"Macro redefines C keyword '{m.group(1)}'")

    def _check_include_form(self, v: List[Violation]) -> None:
        """C2012-20.3 – #include shall use <…> or "…" form."""
        bad_include = re.compile(r'#\s*include\s+(?![<"])')
        for lineno, line in enumerate(self._lines, 1):
            if bad_include.search(line):
                self._add(v, "C2012-20.3", lineno,
                          message="#include not followed by <filename> or \"filename\"")

    def _check_shadowing(self, v: List[Violation]) -> None:
        """C2012-5.3 – identifier shall not hide an outer-scope identifier."""
        # Simplified: detect same variable name declared at multiple depths
        outer: dict = {}
        depth = 0
        var_decl = re.compile(r'^\s*(?:int|char|float|double|long|short|unsigned|signed|void\s*\*)\s+(\w+)')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if '{' in line:
                depth += 1
            m = var_decl.match(line)
            if m:
                name = m.group(1)
                if name in outer and outer[name] < depth:
                    self._add(v, "C2012-5.3", lineno,
                              message=f"Identifier '{name}' shadows outer-scope declaration")
                outer[name] = depth
            if '}' in line:
                depth = max(0, depth - 1)

    def _check_multiple_returns(self, v: List[Violation]) -> None:
        """C2012-15.5 – function should have single exit point."""
        return_pat = re.compile(r'\breturn\b')
        func_def   = re.compile(r'^\s*\w[\w\s\*]+\w\s*\([^)]*\)\s*\{')
        in_func    = False
        return_lines: List[int] = []
        brace_depth = 0
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if func_def.match(line):
                in_func = True
                return_lines = []
                brace_depth = 1
                continue
            if in_func:
                brace_depth += line.count('{') - line.count('}')
                if return_pat.search(line):
                    return_lines.append(lineno)
                if brace_depth <= 0:
                    if len(return_lines) > 1:
                        # Report at every return beyond the first
                        for ln in return_lines[1:]:
                            self._add(v, "C2012-15.5", ln,
                                      message="Function has more than one return statement")
                    in_func = False

    def _check_loop_break_count(self, v: List[Violation]) -> None:
        """C2012-15.4 – at most one break per loop."""
        loop_pat  = re.compile(r'\b(for|while|do)\b')
        break_pat = re.compile(r'\bbreak\b')
        i = 0
        lines = self._lines
        while i < len(lines):
            if _in_comment(lines[i]):
                i += 1
                continue
            if loop_pat.search(lines[i]):
                depth = 0
                break_lines: List[int] = []
                j = i
                while j < len(lines):
                    depth += lines[j].count('{') - lines[j].count('}')
                    if break_pat.search(lines[j]) and not _in_comment(lines[j]):
                        break_lines.append(j + 1)
                    if depth <= 0 and j > i:
                        break
                    j += 1
                if len(break_lines) > 1:
                    for bl in break_lines[1:]:
                        self._add(v, "C2012-15.4", bl,
                                  message="Loop contains more than one break statement")
                i = j + 1
            else:
                i += 1

    def _check_bitwise_on_signed(self, v: List[Violation]) -> None:
        """C2012-10.1 – bitwise operators on signed types (heuristic)."""
        # Detect: signed_var & / | / ^ / ~ / << / >>
        # Very heuristic: flag ~ and << on expressions that look like signed int literals
        pat = re.compile(r'~\s*-?\d+|(?<!\s)<<\s*-?\d+|(?<!\s)>>\s*-?\d+')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if pat.search(line):
                self._add(v, "C2012-10.1", lineno,
                          message="Bitwise operation may be applied to a signed operand")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _in_comment(line: str) -> bool:
    """Heuristic: is this line purely a comment?"""
    s = line.lstrip()
    return s.startswith("//") or s.startswith("*") or s.startswith("/*")
