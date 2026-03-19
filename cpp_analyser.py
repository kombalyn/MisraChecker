"""
MISRA C++:2023 analyser.

Extends C checking with C++-specific patterns:
  - Exception handling rules
  - Dynamic memory (new/delete)
  - auto keyword
  - Namespace using
  - Destructor exception rules
"""

from __future__ import annotations

import re
from typing import List

from ..models import Violation
from .base import BaseAnalyser
from .c_analyser import _in_comment


class CppAnalyser(BaseAnalyser):
    """MISRA C++:2023 static analyser."""

    def _run_checks(self) -> List[Violation]:
        violations: List[Violation] = []
        self._check_goto(violations)
        self._check_recursion(violations)
        self._check_brace_bodies(violations)
        self._check_else_if_else(violations)
        self._check_dynamic_memory(violations)
        self._check_exceptions(violations)
        self._check_auto_usage(violations)
        self._check_using_namespace(violations)
        self._check_cstdarg(violations)
        self._check_return_value(violations)
        self._check_shadowing(violations)
        self._check_errno(violations)
        self._check_empty_catch(violations)
        self._check_destructor_throw(violations)
        self._check_bitwise_signed(violations)
        self._check_multiple_breaks(violations)
        return violations

    # ------------------------------------------------------------------

    def _check_goto(self, v: List[Violation]) -> None:
        """CPP2023-9.5.1"""
        pat = re.compile(r'\bgoto\b')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if pat.search(line):
                self._add(v, "CPP2023-9.5.1", lineno, message="'goto' statement found")

    def _check_recursion(self, v: List[Violation]) -> None:
        """CPP2023-10.0.1"""
        func_def  = re.compile(r'\b(\w+)\s*\([^)]*\)\s*(?:const\s*)?\{')
        func_call = re.compile(r'\b(\w+)\s*\(')
        current   = ""
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            m = func_def.search(line)
            if m:
                current = m.group(1)
            if current:
                for cm in func_call.finditer(line):
                    if cm.group(1) == current and not func_def.search(line):
                        self._add(v, "CPP2023-10.0.1", lineno,
                                  message=f"Recursive call to '{current}'")

    def _check_brace_bodies(self, v: List[Violation]) -> None:
        """CPP2023-9.3.2"""
        pat = re.compile(r'\b(if|else|for|while)\b(?:\s*\([^)]*\))?\s*$')
        brace = re.compile(r'^\s*\{')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if pat.search(line.rstrip()):
                nxt = self._lines[lineno] if lineno < len(self._lines) else ""
                if not brace.match(nxt) and '{' not in line:
                    self._add(v, "CPP2023-9.3.2", lineno,
                              message="Control statement body must be enclosed in braces")

    def _check_else_if_else(self, v: List[Violation]) -> None:
        """CPP2023-9.3.1"""
        elif_pat = re.compile(r'\belse\s+if\b')
        else_pat = re.compile(r'\belse\b(?!\s+if\b)')
        i = 0
        while i < len(self._lines):
            if elif_pat.search(self._lines[i]):
                j = i + 1
                found = False
                while j < min(i + 200, len(self._lines)):
                    if elif_pat.search(self._lines[j]):
                        j += 1
                        continue
                    if else_pat.search(self._lines[j]):
                        found = True
                        break
                    break
                if not found:
                    self._add(v, "CPP2023-9.3.1", i + 1,
                              message="if-else if chain lacks final else clause")
                i = j
            else:
                i += 1

    def _check_dynamic_memory(self, v: List[Violation]) -> None:
        """CPP2023-12.4.1 – new / delete / malloc / free prohibited."""
        pat = re.compile(r'\b(new|delete|malloc|calloc|realloc|free)\b')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            m = pat.search(line)
            if m:
                self._add(v, "CPP2023-12.4.1", lineno,
                          message=f"Dynamic memory operation '{m.group(1)}' is prohibited in safety-critical C++")

    def _check_exceptions(self, v: List[Violation]) -> None:
        """CPP2023-15.0.2 – catch class exceptions by reference."""
        # Detect: catch(SomeType e) without &
        pat = re.compile(r'\bcatch\s*\(\s*(?!\.\.\.)\w[\w:<>*\s]*(?<!&)\s+\w+\s*\)')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if pat.search(line):
                # Exclude catching by value of primitive types
                if re.search(r'\bcatch\s*\(\s*(?:int|long|char|short|double|float|bool)\b', line):
                    continue
                self._add(v, "CPP2023-15.0.2", lineno,
                          message="Exception should be caught by const reference, not by value")

    def _check_auto_usage(self, v: List[Violation]) -> None:
        """CPP2023-7.0.2 – auto should not hide types."""
        pat = re.compile(r'\bauto\b')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if pat.search(line):
                # Allow auto in range-for and lambda
                if re.search(r'for\s*\(\s*auto|auto\s*\(|\[\s*&?\s*\]', line):
                    continue
                self._add(v, "CPP2023-7.0.2", lineno,
                          message="'auto' hides the deduced type; prefer explicit type")

    def _check_using_namespace(self, v: List[Violation]) -> None:
        """CPP2023-5.3.2 – using namespace in header or global scope."""
        pat = re.compile(r'\busing\s+namespace\b')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if pat.search(line):
                self._add(v, "CPP2023-5.3.2", lineno,
                          message="'using namespace' may introduce name conflicts")

    def _check_cstdarg(self, v: List[Violation]) -> None:
        """CPP2023-10.6.1"""
        pat = re.compile(r'#\s*include\s*[<"](cstdarg|stdarg\.h)[>"]')
        for lineno, line in enumerate(self._lines, 1):
            if pat.search(line):
                self._add(v, "CPP2023-10.6.1", lineno,
                          message="<cstdarg> use is prohibited; variadic functions are not type-safe")

    def _check_return_value(self, v: List[Violation]) -> None:
        """CPP2023-10.0.2 – return values shall not be discarded."""
        safe_void = {"cout", "cerr", "printf", "puts", "putchar", "abort", "exit"}
        pat = re.compile(r'^\s*(\w+)\s*[\.:>]+\w+\s*\([^;]*\)\s*;|^\s*(\w+)\s*\([^;]*\)\s*;')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            m = pat.match(line)
            if m:
                fn = (m.group(1) or m.group(2) or "")
                if fn in ("if", "for", "while", "switch", "return", "else", "delete"):
                    continue
                if fn in {"fclose", "fopen", "remove", "rename", "system", "fflush",
                          "pthread_create", "pthread_join"}:
                    self._add(v, "CPP2023-10.0.2", lineno,
                              message=f"Return value of '{fn}()' is discarded")

    def _check_shadowing(self, v: List[Violation]) -> None:
        """CPP2023-5.3.1"""
        outer: dict = {}
        depth = 0
        decl = re.compile(r'^\s*(?:int|char|float|double|bool|auto|long|short|std::string|string)\s+(\w+)')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            depth += line.count('{') - line.count('}')
            m = decl.match(line)
            if m:
                name = m.group(1)
                if name in outer and outer[name] < depth:
                    self._add(v, "CPP2023-5.3.1", lineno,
                              message=f"Identifier '{name}' shadows an outer-scope declaration")
                outer[name] = depth

    def _check_errno(self, v: List[Violation]) -> None:
        """CPP2023-19.0.1 – errno shall not be used."""
        pat = re.compile(r'\berrno\b')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if pat.search(line):
                self._add(v, "CPP2023-19.0.1", lineno,
                          message="'errno' is not thread-safe; use exception-based error handling")

    def _check_empty_catch(self, v: List[Violation]) -> None:
        """CPP2023-15.0.3 – empty catch blocks."""
        catch_pat = re.compile(r'\bcatch\b')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if catch_pat.search(line):
                # Look ahead for { ... } with only whitespace or comments
                body = ""
                for offset in range(1, 6):
                    idx = lineno - 1 + offset
                    if idx < len(self._lines):
                        body += self._lines[idx]
                        if '}' in body:
                            break
                # Strip whitespace and comments
                body_clean = re.sub(r'//[^\n]*', '', body)
                body_clean = body_clean.replace('\n', '').strip()
                if body_clean in ('{}', '{', '}', '{ }'):
                    self._add(v, "CPP2023-15.0.3", lineno,
                              message="Empty catch block silently swallows exceptions")

    def _check_destructor_throw(self, v: List[Violation]) -> None:
        """CPP2023-15.0.4 – destructors shall not throw."""
        in_dtor = False
        dtor_pat = re.compile(r'~\w+\s*\(')
        throw_pat = re.compile(r'\bthrow\b')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if dtor_pat.search(line):
                in_dtor = True
            if in_dtor and throw_pat.search(line):
                self._add(v, "CPP2023-15.0.4", lineno,
                          message="Exception thrown from destructor – may call std::terminate()")
            if in_dtor and '}' in line:
                in_dtor = False

    def _check_bitwise_signed(self, v: List[Violation]) -> None:
        """CPP2023-7.0.1 – bitwise ops on signed types."""
        pat = re.compile(r'~\s*-?\d+|\b(int|signed)\b[^;]*(<<|>>|&|\||\^)')
        for lineno, line in enumerate(self._lines, 1):
            if _in_comment(line):
                continue
            if pat.search(line):
                self._add(v, "CPP2023-7.0.1", lineno,
                          message="Bitwise operator applied to potentially signed operand")

    def _check_multiple_breaks(self, v: List[Violation]) -> None:
        """CPP2023-9.5.2 – at most one break per loop."""
        loop_pat  = re.compile(r'\b(for|while|do)\b')
        break_pat = re.compile(r'\bbreak\b')
        i = 0
        while i < len(self._lines):
            if loop_pat.search(self._lines[i]):
                depth = 0
                breaks: List[int] = []
                j = i
                while j < len(self._lines):
                    depth += self._lines[j].count('{') - self._lines[j].count('}')
                    if break_pat.search(self._lines[j]) and not _in_comment(self._lines[j]):
                        breaks.append(j + 1)
                    if depth <= 0 and j > i:
                        break
                    j += 1
                if len(breaks) > 1:
                    for bl in breaks[1:]:
                        self._add(v, "CPP2023-9.5.2", bl,
                                  message="Loop has more than one break statement")
                i = j + 1
            else:
                i += 1
