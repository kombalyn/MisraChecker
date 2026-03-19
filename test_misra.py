"""
Test suite for MISRA Compliance Checker.
Run with: pytest tests/ -v
"""

from __future__ import annotations

import pytest
from pathlib import Path
from misra_checker import MISRAChecker, Standard, Severity


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def c_checker():
    return MISRAChecker(standard=Standard.C2012)

@pytest.fixture
def cpp_checker():
    return MISRAChecker(standard=Standard.CPP2023)

@pytest.fixture
def py_checker():
    return MISRAChecker(standard=Standard.PY2024)


# ---------------------------------------------------------------------------
# MISRA C:2012
# ---------------------------------------------------------------------------

class TestMISRA_C_2012:

    def test_goto_detected(self, c_checker):
        src = "void f(void) { goto label; label: return; }"
        r = c_checker.check_string(src, "test.c")
        ids = [v.rule_id for v in r.violations]
        assert "C2012-15.1" in ids

    def test_no_goto_clean(self, c_checker):
        src = "void f(void) { int x = 1; return; }"
        r = c_checker.check_string(src, "test.c")
        assert "C2012-15.1" not in [v.rule_id for v in r.violations]

    def test_float_loop_counter(self, c_checker):
        src = "void f(void) { for (float i = 0; i < 10; i++) {} }"
        r = c_checker.check_string(src, "test.c")
        assert "C2012-14.1" in [v.rule_id for v in r.violations]

    def test_sizeof_side_effect(self, c_checker):
        src = "void f(void) { int x = 0; int s = sizeof(x++); }"
        r = c_checker.check_string(src, "test.c")
        assert "C2012-13.6" in [v.rule_id for v in r.violations]

    def test_stdarg_include(self, c_checker):
        src = '#include <stdarg.h>\nvoid f(int n, ...) {}'
        r = c_checker.check_string(src, "test.c")
        assert "C2012-17.1" in [v.rule_id for v in r.violations]

    def test_macro_redefines_keyword(self, c_checker):
        src = '#define int long\nvoid f(void) {}'
        r = c_checker.check_string(src, "test.c")
        assert "C2012-20.4" in [v.rule_id for v in r.violations]

    def test_logical_rhs_side_effect(self, c_checker):
        src = "void f(void) { int a=0,b=0; if (a && b++) {} }"
        r = c_checker.check_string(src, "test.c")
        assert "C2012-13.5" in [v.rule_id for v in r.violations]

    def test_return_value_discarded(self, c_checker):
        src = "void f(void) { fclose(0); }"
        r = c_checker.check_string(src, "test.c")
        assert "C2012-17.7" in [v.rule_id for v in r.violations]

    def test_multiple_returns(self, c_checker):
        src = "int f(int x) {\n  if (x) return 1;\n  return 0;\n}\n"
        r = c_checker.check_string(src, "test.c")
        assert "C2012-15.5" in [v.rule_id for v in r.violations]

    def test_else_if_without_else(self, c_checker):
        src = "void f(int x) {\n  if (x==1) {}\n  else if (x==2) {}\n}\n"
        r = c_checker.check_string(src, "test.c")
        assert "C2012-15.7" in [v.rule_id for v in r.violations]

    def test_else_if_with_else_ok(self, c_checker):
        src = "void f(int x) {\n  if (x==1) {}\n  else if (x==2) {}\n  else {}\n}\n"
        r = c_checker.check_string(src, "test.c")
        assert "C2012-15.7" not in [v.rule_id for v in r.violations]

    def test_malloc_without_free(self, c_checker):
        src = "#include <stdlib.h>\nvoid f(void) { int *p = malloc(4); *p = 1; }"
        r = c_checker.check_string(src, "test.c")
        assert "C2012-22.1" in [v.rule_id for v in r.violations]

    def test_is_compliant_clean(self, c_checker):
        src = "int add(int a, int b) { return a + b; }\n"
        r = c_checker.check_string(src, "test.c")
        mandatory_required = [v for v in r.violations
                              if v.severity in (Severity.MANDATORY, Severity.REQUIRED)]
        assert len(mandatory_required) == 0

    def test_inline_suppression(self):
        checker = MISRAChecker(standard=Standard.C2012, suppress_comments=True)
        src = "void f(void) { goto end; // MISRA-suppress: C2012-15.1 intentional\nend: return; }"
        r = checker.check_string(src, "test.c")
        suppressed = [v for v in r.violations if v.rule_id == "C2012-15.1" and v.suppressed]
        assert len(suppressed) == 1


# ---------------------------------------------------------------------------
# MISRA C++:2023
# ---------------------------------------------------------------------------

class TestMISRA_CPP_2023:

    def test_dynamic_memory_new(self, cpp_checker):
        src = "void f() { int* p = new int(5); delete p; }"
        r = cpp_checker.check_string(src, "test.cpp")
        assert "CPP2023-12.4.1" in [v.rule_id for v in r.violations]

    def test_goto_detected(self, cpp_checker):
        src = "void f() { goto end; end: return; }"
        r = cpp_checker.check_string(src, "test.cpp")
        assert "CPP2023-9.5.1" in [v.rule_id for v in r.violations]

    def test_errno_usage(self, cpp_checker):
        src = "#include <cerrno>\nvoid f() { if (errno != 0) {} }"
        r = cpp_checker.check_string(src, "test.cpp")
        assert "CPP2023-19.0.1" in [v.rule_id for v in r.violations]

    def test_catch_by_value(self, cpp_checker):
        src = "void f() { try {} catch(std::exception e) {} }"
        r = cpp_checker.check_string(src, "test.cpp")
        assert "CPP2023-15.0.2" in [v.rule_id for v in r.violations]

    def test_cstdarg_include(self, cpp_checker):
        src = "#include <cstdarg>\nvoid f(int n, ...) {}"
        r = cpp_checker.check_string(src, "test.cpp")
        assert "CPP2023-10.6.1" in [v.rule_id for v in r.violations]

    def test_using_namespace(self, cpp_checker):
        src = "using namespace std;\nvoid f() {}"
        r = cpp_checker.check_string(src, "test.cpp")
        assert "CPP2023-5.3.2" in [v.rule_id for v in r.violations]

    def test_auto_variable(self, cpp_checker):
        src = "void f() { auto x = 42; }"
        r = cpp_checker.check_string(src, "test.cpp")
        assert "CPP2023-7.0.2" in [v.rule_id for v in r.violations]

    def test_destructor_throw(self, cpp_checker):
        src = "class A { ~A() { throw 1; } };"
        r = cpp_checker.check_string(src, "test.cpp")
        assert "CPP2023-15.0.4" in [v.rule_id for v in r.violations]


# ---------------------------------------------------------------------------
# MISRA Python:2024
# ---------------------------------------------------------------------------

class TestMISRA_PY_2024:

    def test_wildcard_import(self, py_checker):
        src = "from os import *\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-1.1" in [v.rule_id for v in r.violations]

    def test_none_comparison(self, py_checker):
        src = "x = None\nif x == None: pass\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-3.1" in [v.rule_id for v in r.violations]

    def test_none_is_ok(self, py_checker):
        src = "x = None\nif x is None: pass\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-3.1" not in [v.rule_id for v in r.violations]

    def test_bool_comparison(self, py_checker):
        src = "x = True\nif x == True: pass\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-3.2" in [v.rule_id for v in r.violations]

    def test_eval_prohibited(self, py_checker):
        src = 'result = eval("1+2")\n'
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-8.1" in [v.rule_id for v in r.violations]

    def test_exec_prohibited(self, py_checker):
        src = 'exec("x = 1")\n'
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-8.1" in [v.rule_id for v in r.violations]

    def test_global_statement(self, py_checker):
        src = "counter = 0\ndef inc():\n    global counter\n    counter += 1\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-8.2" in [v.rule_id for v in r.violations]

    def test_assert_statement(self, py_checker):
        src = "def f(x):\n    assert x > 0\n    return x\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-8.3" in [v.rule_id for v in r.violations]

    def test_bare_except(self, py_checker):
        src = "try:\n    pass\nexcept:\n    pass\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-6.1" in [v.rule_id for v in r.violations]

    def test_specific_except_ok(self, py_checker):
        src = "try:\n    pass\nexcept ValueError:\n    pass\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-6.1" not in [v.rule_id for v in r.violations]

    def test_missing_type_annotations(self, py_checker):
        src = "def add(a, b):\n    return a + b\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-5.1" in [v.rule_id for v in r.violations]

    def test_type_annotations_ok(self, py_checker):
        src = "def add(a: int, b: int) -> int:\n    return a + b\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-5.1" not in [v.rule_id for v in r.violations]

    def test_mutable_default(self, py_checker):
        src = "def f(items=[]):\n    items.append(1)\n    return items\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-5.2" in [v.rule_id for v in r.violations]

    def test_recursion_detected(self, py_checker):
        src = "def factorial(n: int) -> int:\n    return n * factorial(n-1)\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-5.3" in [v.rule_id for v in r.violations]

    def test_continue_prohibited(self, py_checker):
        src = "for i in range(10):\n    if i == 5:\n        continue\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-4.3" in [v.rule_id for v in r.violations]

    def test_duplicate_import(self, py_checker):
        src = "import os\nimport os\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-1.3" in [v.rule_id for v in r.violations]

    def test_dunder_import(self, py_checker):
        src = "mod = __import__('os')\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-8.4" in [v.rule_id for v in r.violations]

    def test_class_naming_violation(self, py_checker):
        src = "class my_class:\n    pass\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-2.2" in [v.rule_id for v in r.violations]

    def test_class_naming_ok(self, py_checker):
        src = "class MyClass:\n    pass\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-2.2" not in [v.rule_id for v in r.violations]

    def test_if_elif_without_else(self, py_checker):
        src = (
            "def f(x: int) -> str:\n"
            "    if x == 1:\n"
            "        return 'one'\n"
            "    elif x == 2:\n"
            "        return 'two'\n"
        )
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-4.1" in [v.rule_id for v in r.violations]

    def test_if_elif_with_else_ok(self, py_checker):
        src = (
            "def f(x: int) -> str:\n"
            "    if x == 1:\n"
            "        return 'one'\n"
            "    elif x == 2:\n"
            "        return 'two'\n"
            "    else:\n"
            "        return 'other'\n"
        )
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-4.1" not in [v.rule_id for v in r.violations]

    def test_too_many_parameters(self, py_checker):
        src = "def f(a: int, b: int, c: int, d: int, e: int, f: int) -> None:\n    pass\n"
        r = py_checker.check_string(src, "test.py")
        assert "PY2024-5.5" in [v.rule_id for v in r.violations]


# ---------------------------------------------------------------------------
# Report output formats
# ---------------------------------------------------------------------------

class TestReportFormats:

    def test_json_output(self, py_checker):
        import json
        src = "from os import *\n"
        r = py_checker.check_string(src, "test.py")
        data = json.loads(r.to_json())
        assert "violations" in data
        assert "compliant" in data

    def test_sarif_output(self, py_checker):
        src = "from os import *\n"
        r = py_checker.check_string(src, "test.py")
        sarif = r.to_sarif()
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif

    def test_summary_contains_status(self, py_checker):
        src = "import os\n"
        r = py_checker.check_string(src, "test.py")
        summary = r.summary()
        assert "COMPLIANT" in summary or "NON-COMPLIANT" in summary


# ---------------------------------------------------------------------------
# Auto-detection
# ---------------------------------------------------------------------------

class TestAutoDetection:

    def test_py_auto_detected(self):
        checker = MISRAChecker()  # no standard forced
        src = "from os import *\n"
        r = checker.check_string(src, "script.py")
        assert r.standard == Standard.PY2024

    def test_c_auto_detected(self):
        checker = MISRAChecker()
        src = "void f(void) { goto end; end: return; }\n"
        r = checker.check_string(src, "main.c")
        assert r.standard == Standard.C2012

    def test_cpp_auto_detected(self):
        checker = MISRAChecker()
        src = "void f() { int* p = new int(1); delete p; }\n"
        r = checker.check_string(src, "app.cpp")
        assert r.standard == Standard.CPP2023


# ---------------------------------------------------------------------------
# Severity filter
# ---------------------------------------------------------------------------

class TestSeverityFilter:

    def test_advisory_filtered_out(self):
        checker = MISRAChecker(
            standard=Standard.PY2024,
            severity_filter=["mandatory", "required"],
        )
        # PY2024-8.3 (assert) is advisory – should be filtered
        src = "def f(x: int) -> int:\n    assert x > 0\n    return x\n"
        r = checker.check_string(src, "test.py")
        assert "PY2024-8.3" not in [v.rule_id for v in r.violations]


# ---------------------------------------------------------------------------
# Rule disable / enable
# ---------------------------------------------------------------------------

class TestRuleFilters:

    def test_disable_rule(self):
        checker = MISRAChecker(
            standard=Standard.PY2024,
            disabled_rules=["PY2024-8.3"],
        )
        src = "def f(x: int) -> int:\n    assert x > 0\n    return x\n"
        r = checker.check_string(src, "test.py")
        assert "PY2024-8.3" not in [v.rule_id for v in r.violations]

    def test_enable_only_specific_rule(self):
        checker = MISRAChecker(
            standard=Standard.PY2024,
            enabled_rules=["PY2024-1.1"],
        )
        src = "from os import *\nassert True\n"
        r = checker.check_string(src, "test.py")
        ids = [v.rule_id for v in r.violations]
        assert "PY2024-1.1" in ids
        assert "PY2024-8.3" not in ids


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class TestRegistry:

    def test_all_standards_have_rules(self):
        from misra_checker.rules.registry import get_rules_for_standard
        for std in Standard:
            rules = get_rules_for_standard(std)
            assert len(rules) > 0, f"No rules found for {std}"

    def test_get_rule_by_id(self):
        from misra_checker.rules.registry import get_rule
        rule = get_rule("C2012-15.1")
        assert rule is not None
        assert rule.severity == Severity.ADVISORY

    def test_get_unknown_rule(self):
        from misra_checker.rules.registry import get_rule
        assert get_rule("NONEXISTENT-0.0") is None
