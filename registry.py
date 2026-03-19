"""
MISRA rule registry – single source of truth for all rule metadata.

Rules are stored as plain Python dicts then materialised into RuleSpec
objects on first access. This keeps the module importable with zero
dependencies.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Dict, List, Optional

from ..models import RuleCategory, RuleSpec, Severity, Standard


# ---------------------------------------------------------------------------
# Raw rule tables
# Format: (rule_id, category, severity, title, description, rationale)
# ---------------------------------------------------------------------------

_C2012_RULES_RAW: List[tuple] = [
    # --- Directives (Dir) ---
    ("C2012-Dir4.1", RuleCategory.LANGUAGE_EXTENSIONS, Severity.REQUIRED,
     "Run-time failures shall be minimised",
     "Code shall be designed to avoid undefined/unspecified behaviour at run-time.",
     "Undefined behaviour can cause silent data corruption or safety hazards."),

    # --- Preprocessing ---
    ("C2012-20.1", RuleCategory.PREPROCESSING, Severity.ADVISORY,
     "#include directives shall only be preceded by preprocessor or comment lines",
     "Only preprocessor directives and comments shall precede #include.",
     "Mixing code with includes reduces readability and portability."),
    ("C2012-20.2", RuleCategory.PREPROCESSING, Severity.REQUIRED,
     "The ', \" or \\ characters shall not occur in a header file name",
     "Header file names shall not contain ', \", or \\ characters.",
     "These characters have special meaning and cause portability issues."),
    ("C2012-20.3", RuleCategory.PREPROCESSING, Severity.REQUIRED,
     "The #include directive shall be followed by either a <filename> or \"filename\"",
     "The #include directive shall use the standard file name forms.",
     "Non-standard forms invoke undefined behaviour."),
    ("C2012-20.4", RuleCategory.PREPROCESSING, Severity.MANDATORY,
     "A macro shall not be defined with the same name as a keyword",
     "Macro names shall not match C keywords.",
     "Redefining keywords causes undefined/unspecified behaviour."),
    ("C2012-20.9", RuleCategory.PREPROCESSING, Severity.REQUIRED,
     "All identifiers used in #if and #elif shall be defined",
     "Undefined identifiers in preprocessor conditions evaluate to 0 silently.",
     "Silent zero evaluation can lead to wrong conditional compilation."),
    ("C2012-20.10", RuleCategory.PREPROCESSING, Severity.ADVISORY,
     "The # and ## operators should not be used",
     "Token pasting and stringization operators make code hard to understand.",
     "These operators can produce surprising results."),
    ("C2012-20.12", RuleCategory.PREPROCESSING, Severity.REQUIRED,
     "A macro parameter used as an operand of # or ## shall only be used once",
     "Multiple use of a macro parameter combined with # or ## is undefined.",
     "Undefined behaviour may occur."),

    # --- Declarations ---
    ("C2012-8.1",  RuleCategory.DECLARATIONS, Severity.REQUIRED,
     "Types shall be explicitly specified",
     "Implicit int and implicit function declarations are not permitted.",
     "Implicit types reduce portability and obscure intent."),
    ("C2012-8.2",  RuleCategory.DECLARATIONS, Severity.REQUIRED,
     "Function types shall be in prototype form",
     "All function declarations shall include parameter types.",
     "Non-prototype forms allow incorrect calls to go undetected."),
    ("C2012-8.4",  RuleCategory.DECLARATIONS, Severity.REQUIRED,
     "A compatible declaration shall be visible when an object or function with external linkage is defined",
     "Extern declarations must match definitions.",
     "Mismatches cause undefined behaviour."),
    ("C2012-8.7",  RuleCategory.DECLARATIONS, Severity.ADVISORY,
     "Functions and objects should not be defined with external linkage when only used in one TU",
     "Use static linkage for objects/functions used only in one translation unit.",
     "Minimises namespace pollution."),
    ("C2012-8.9",  RuleCategory.DECLARATIONS, Severity.ADVISORY,
     "An object should be defined at block scope if only accessed from within a single function",
     "Prefer local variables to unnecessary globals.",
     "Globals increase coupling and make reasoning about state harder."),

    # --- Identifiers ---
    ("C2012-5.1",  RuleCategory.IDENTIFIERS, Severity.REQUIRED,
     "External identifiers shall be distinct in the first 31 characters",
     "The first 31 characters of external identifiers shall be unique.",
     "Some linkers only compare a limited number of characters."),
    ("C2012-5.2",  RuleCategory.IDENTIFIERS, Severity.REQUIRED,
     "Identifiers declared in the same scope shall be distinct",
     "No two identifiers in the same scope shall be identical.",
     "Duplicate names cause confusion and potential errors."),
    ("C2012-5.3",  RuleCategory.IDENTIFIERS, Severity.REQUIRED,
     "An identifier declared in an inner scope shall not hide an identifier in an outer scope",
     "Identifier shadowing shall be avoided.",
     "Shadowing makes code harder to understand and error-prone."),
    ("C2012-5.4",  RuleCategory.IDENTIFIERS, Severity.REQUIRED,
     "Macro identifiers shall be distinct in the first 63 characters",
     "First 63 characters of macro names shall be unique.",
     "Longer macro names may be silently truncated."),

    # --- Types ---
    ("C2012-10.1", RuleCategory.TYPES, Severity.REQUIRED,
     "Operands shall not be of an inappropriate essential type",
     "Each operand shall have the essential type appropriate for the operator.",
     "Inappropriate types lead to unexpected results."),
    ("C2012-10.3", RuleCategory.TYPES, Severity.REQUIRED,
     "The value of an expression shall not be assigned to an object of a narrower essential type",
     "Assignments shall not narrow values.",
     "Narrowing can silently truncate values."),
    ("C2012-10.4", RuleCategory.TYPES, Severity.REQUIRED,
     "Both operands of an operator in which the usual arithmetic conversions are performed shall have the same essential type",
     "Mixed-type arithmetic operands require explicit casts.",
     "Implicit conversions may produce unexpected results."),

    # --- Conversions ---
    ("C2012-10.5", RuleCategory.CONVERSIONS, Severity.ADVISORY,
     "The value of an expression should not be cast to an inappropriate essential type",
     "Casts to inappropriate types should be avoided.",
     "Inappropriate casts can cause data loss."),
    ("C2012-10.6", RuleCategory.CONVERSIONS, Severity.REQUIRED,
     "The value of a composite expression shall not be assigned to an object of wider essential type without a cast",
     "Composite expressions assigned to wider types need explicit cast.",
     "Implicit widening conversions may not be intentional."),
    ("C2012-10.8", RuleCategory.CONVERSIONS, Severity.REQUIRED,
     "The value of a composite expression shall not be cast to a different essential type or a wider essential type",
     "Composite expression casts to wider/different types are prohibited.",
     "Such casts may lose information."),

    # --- Expressions ---
    ("C2012-13.1", RuleCategory.EXPRESSIONS, Severity.REQUIRED,
     "Initializer lists shall not contain persistent side effects",
     "Side effects in initializer lists can lead to unspecified behaviour.",
     "Order of evaluation of initializer lists is unspecified."),
    ("C2012-13.2", RuleCategory.EXPRESSIONS, Severity.REQUIRED,
     "The value of an expression and its persistent side effects shall be the same under all permitted evaluation orders",
     "Expressions shall not depend on evaluation order.",
     "Evaluation order is implementation-defined in many contexts."),
    ("C2012-13.3", RuleCategory.EXPRESSIONS, Severity.ADVISORY,
     "A full expression containing an increment (++) or decrement (--) operator should have no other potential side effects",
     "Avoid multiple side effects in one expression.",
     "Combining ++ with other side effects is confusing."),
    ("C2012-13.4", RuleCategory.EXPRESSIONS, Severity.ADVISORY,
     "The result of an assignment shall not be used",
     "Assignment results shall not be used as sub-expressions.",
     "Using assignment results in expressions obscures intent."),
    ("C2012-13.5", RuleCategory.EXPRESSIONS, Severity.REQUIRED,
     "The right-hand operand of a logical && or || shall not contain persistent side effects",
     "No side effects in right-hand operand of && or ||.",
     "Short-circuit evaluation may skip right-hand side."),
    ("C2012-13.6", RuleCategory.EXPRESSIONS, Severity.MANDATORY,
     "The operand of the sizeof operator shall not contain any expression which has a potential side effect",
     "sizeof operand shall not have side effects.",
     "sizeof does not evaluate its operand; side effects would be silently skipped."),

    # --- Control flow ---
    ("C2012-14.1", RuleCategory.CONTROL_FLOW, Severity.REQUIRED,
     "A loop counter shall not have essentially floating-point type",
     "Floating-point loop counters are prohibited.",
     "Floating-point representation errors make loop termination uncertain."),
    ("C2012-14.2", RuleCategory.CONTROL_FLOW, Severity.REQUIRED,
     "A for loop shall be well-formed",
     "for loop init, condition, and increment shall be simple and non-empty.",
     "Complex for loops obscure loop termination."),
    ("C2012-14.3", RuleCategory.CONTROL_FLOW, Severity.REQUIRED,
     "Controlling expressions shall not be invariant",
     "Loop/if controlling expressions shall not always be true or false.",
     "Invariant conditions indicate dead code or logic errors."),
    ("C2012-14.4", RuleCategory.CONTROL_FLOW, Severity.REQUIRED,
     "The controlling expression of an if statement shall be essentially Boolean",
     "if conditions shall be Boolean, not integer or pointer.",
     "Non-Boolean conditions lead to subtle bugs."),
    ("C2012-14.5", RuleCategory.CONTROL_FLOW, Severity.ADVISORY,
     "A for loop shall contain a single break or goto statement at most",
     "Loops should have a single exit point.",
     "Multiple exits make loop behaviour harder to reason about."),
    ("C2012-15.1", RuleCategory.CONTROL_FLOW, Severity.ADVISORY,
     "The goto statement should not be used",
     "goto shall not be used.",
     "goto makes control flow hard to follow and analyse."),
    ("C2012-15.2", RuleCategory.CONTROL_FLOW, Severity.REQUIRED,
     "The goto statement shall jump to a label declared later in the same function",
     "goto shall only jump forward in the same function.",
     "Backward gotos make loops that bypass loop analysis."),
    ("C2012-15.3", RuleCategory.CONTROL_FLOW, Severity.REQUIRED,
     "Any label referenced by a goto shall be declared in the same block or enclosing block",
     "goto target shall be in same or enclosing block.",
     "Out-of-block jumps bypass variable initialisation."),
    ("C2012-15.4", RuleCategory.CONTROL_FLOW, Severity.ADVISORY,
     "There should be no more than one break statement used to terminate any loop",
     "Loops should have at most one break.",
     "Multiple breaks complicate exit analysis."),
    ("C2012-15.5", RuleCategory.CONTROL_FLOW, Severity.ADVISORY,
     "A function should have a single point of exit",
     "Functions should have only one return statement.",
     "Multiple returns complicate reasoning about postconditions."),
    ("C2012-15.6", RuleCategory.CONTROL_FLOW, Severity.REQUIRED,
     "The body of an iteration-statement or a selection-statement shall be a compound statement",
     "if/for/while bodies shall use braces.",
     "Braceless bodies are error-prone when adding statements."),
    ("C2012-15.7", RuleCategory.CONTROL_FLOW, Severity.REQUIRED,
     "All if...else if constructs shall be terminated with an else clause",
     "if-else if chains shall end with an else clause.",
     "Missing else may indicate incomplete handling."),

    # --- Functions ---
    ("C2012-17.1", RuleCategory.FUNCTIONS, Severity.MANDATORY,
     "The features of <stdarg.h> shall not be used",
     "Variable argument functions are prohibited.",
     "Variadic functions cannot be type-checked by the compiler."),
    ("C2012-17.2", RuleCategory.FUNCTIONS, Severity.REQUIRED,
     "Functions shall not call themselves, either directly or indirectly",
     "Recursion is prohibited.",
     "Recursion can cause unbounded stack growth."),
    ("C2012-17.3", RuleCategory.FUNCTIONS, Severity.MANDATORY,
     "A function shall not be declared implicitly",
     "All functions shall be declared before use.",
     "Implicit declarations allow type mismatches."),
    ("C2012-17.4", RuleCategory.FUNCTIONS, Severity.MANDATORY,
     "All exit paths from a function with non-void return type shall have an explicit return statement with an expression",
     "Non-void functions shall return a value on all paths.",
     "Missing return produces undefined behaviour."),
    ("C2012-17.7", RuleCategory.FUNCTIONS, Severity.REQUIRED,
     "The value returned by a function having non-void return type shall be used",
     "Return values shall not be silently discarded.",
     "Discarded return values may indicate missing error handling."),

    # --- Pointers ---
    ("C2012-11.1", RuleCategory.POINTERS_ARRAYS, Severity.REQUIRED,
     "Conversions shall not be performed between a pointer to a function and any other type",
     "Function pointer conversions to/from other types are prohibited.",
     "Such conversions invoke undefined behaviour."),
    ("C2012-11.2", RuleCategory.POINTERS_ARRAYS, Severity.REQUIRED,
     "Conversions shall not be performed between a pointer to an incomplete type and any other type",
     "Incomplete-type pointer conversions are prohibited.",
     "Dereferencing such a pointer is undefined behaviour."),
    ("C2012-11.3", RuleCategory.POINTERS_ARRAYS, Severity.REQUIRED,
     "A cast shall not be performed between a pointer to object type and a pointer to a different object type",
     "Pointer casts between different object types are prohibited.",
     "Alignment requirements may be violated."),
    ("C2012-11.4", RuleCategory.POINTERS_ARRAYS, Severity.ADVISORY,
     "A conversion should not be performed between a pointer to object and an integer type",
     "Pointer-to-integer conversions should be avoided.",
     "The result is implementation-defined."),
    ("C2012-11.5", RuleCategory.POINTERS_ARRAYS, Severity.ADVISORY,
     "A conversion should not be performed from pointer to void into pointer to object",
     "void* to object pointer conversions should be avoided.",
     "Alignment requirements may not be met."),

    # --- Memory ---
    ("C2012-22.1", RuleCategory.MEMORY, Severity.REQUIRED,
     "All resources obtained dynamically by means of Standard Library functions shall be explicitly released",
     "malloc/calloc allocations shall be freed.",
     "Memory leaks degrade reliability over time."),
    ("C2012-22.2", RuleCategory.MEMORY, Severity.MANDATORY,
     "A block of memory shall only be freed if it was allocated by means of a Standard Library function",
     "Only free memory allocated by stdlib functions.",
     "Freeing non-heap memory is undefined behaviour."),
    ("C2012-22.3", RuleCategory.MEMORY, Severity.REQUIRED,
     "The same file shall not be opened more than once at the same time",
     "A file shall not be opened more than once simultaneously.",
     "Concurrent access can corrupt file state."),
    ("C2012-22.6", RuleCategory.MEMORY, Severity.MANDATORY,
     "The value of a pointer to a FILE shall not be used after the associated stream is closed",
     "FILE pointers shall not be used after fclose.",
     "Using a closed FILE pointer is undefined behaviour."),
]


_CPP2023_RULES_RAW: List[tuple] = [
    # --- Language extensions ---
    ("CPP2023-0.1.1", RuleCategory.LANGUAGE_EXTENSIONS, Severity.REQUIRED,
     "A project shall not contain unreachable code",
     "Unreachable code shall be removed.",
     "Dead code indicates logic errors and increases maintenance burden."),
    ("CPP2023-0.1.2", RuleCategory.LANGUAGE_EXTENSIONS, Severity.REQUIRED,
     "A project shall not contain unused variables",
     "Variables that are declared but never used shall be removed.",
     "Unused variables may indicate missing functionality or copy-paste errors."),

    # --- Declarations ---
    ("CPP2023-6.4.1", RuleCategory.DECLARATIONS, Severity.REQUIRED,
     "All variables shall be initialised before use",
     "Variables shall be given a value before they are read.",
     "Reading uninitialised variables is undefined behaviour in C++."),
    ("CPP2023-6.4.2", RuleCategory.DECLARATIONS, Severity.ADVISORY,
     "Variables shall be declared as locally as possible",
     "Declare variables in the innermost scope where they are used.",
     "Minimises lifetime and reduces accidental reuse."),
    ("CPP2023-6.5.1", RuleCategory.DECLARATIONS, Severity.REQUIRED,
     "A function shall return a value on all code paths",
     "Non-void functions shall have a return statement on every path.",
     "Falling off the end of a non-void function is undefined behaviour."),

    # --- Types ---
    ("CPP2023-7.0.1", RuleCategory.TYPES, Severity.REQUIRED,
     "Operands of bitwise operators shall have unsigned underlying type",
     "Bitwise operations shall only be applied to unsigned types.",
     "Bitwise operations on signed types produce implementation-defined results."),
    ("CPP2023-7.0.2", RuleCategory.TYPES, Severity.REQUIRED,
     "The auto specifier shall not be used to declare variables with deduced type",
     "auto deduced types shall be used only when the type is otherwise verbose.",
     "auto can hide important type information."),

    # --- Expressions ---
    ("CPP2023-8.0.1", RuleCategory.EXPRESSIONS, Severity.REQUIRED,
     "Operands shall not be of inappropriate essential type",
     "Types of operands shall match the operator requirements.",
     "Inappropriate types produce implementation-defined behaviour."),
    ("CPP2023-8.3.1", RuleCategory.EXPRESSIONS, Severity.ADVISORY,
     "Compound expressions shall not include sub-expressions with side effects",
     "Side effects in compound expressions should be avoided.",
     "Order of evaluation is unspecified."),

    # --- Control flow ---
    ("CPP2023-9.3.1", RuleCategory.CONTROL_FLOW, Severity.REQUIRED,
     "All if-else-if constructs shall be terminated with a final else clause",
     "if-else-if chains shall end with else.",
     "Missing else may leave unhandled cases."),
    ("CPP2023-9.3.2", RuleCategory.CONTROL_FLOW, Severity.REQUIRED,
     "Bodies of if/for/while/do statements shall be enclosed in braces",
     "Control-flow statement bodies shall use compound statements.",
     "Braceless bodies are error-prone."),
    ("CPP2023-9.5.1", RuleCategory.CONTROL_FLOW, Severity.ADVISORY,
     "The goto statement shall not be used",
     "goto is prohibited in C++.",
     "goto creates unstructured control flow."),
    ("CPP2023-9.5.2", RuleCategory.CONTROL_FLOW, Severity.REQUIRED,
     "Loop body shall not contain more than one break",
     "At most one break per loop.",
     "Multiple breaks create complex exit logic."),

    # --- Functions ---
    ("CPP2023-10.0.1", RuleCategory.FUNCTIONS, Severity.REQUIRED,
     "Functions shall not call themselves recursively",
     "Recursive calls are prohibited.",
     "Recursion can cause stack overflow in embedded/safety-critical contexts."),
    ("CPP2023-10.0.2", RuleCategory.FUNCTIONS, Severity.REQUIRED,
     "The value returned by a non-void function call shall be used",
     "Discarding return values is prohibited.",
     "Discarded return values often indicate missed error handling."),
    ("CPP2023-10.6.1", RuleCategory.FUNCTIONS, Severity.MANDATORY,
     "The features of <cstdarg> shall not be used",
     "Variadic functions via cstdarg are prohibited.",
     "Variadic argument passing is not type-safe."),

    # --- Exceptions ---
    ("CPP2023-15.0.1", RuleCategory.EXCEPTIONS, Severity.REQUIRED,
     "Exceptions shall not be used for normal control flow",
     "Exceptions shall only be used for error conditions.",
     "Using exceptions for control flow is inefficient and obscures intent."),
    ("CPP2023-15.0.2", RuleCategory.EXCEPTIONS, Severity.REQUIRED,
     "A class-type exception shall be caught by reference",
     "Catch class exceptions by const reference.",
     "Catching by value causes slicing; by pointer may leak."),
    ("CPP2023-15.0.3", RuleCategory.EXCEPTIONS, Severity.ADVISORY,
     "An empty exception handler (catch block) shall not be used",
     "catch blocks shall not be empty.",
     "Empty catch blocks silently swallow errors."),
    ("CPP2023-15.0.4", RuleCategory.EXCEPTIONS, Severity.REQUIRED,
     "Destructors shall not exit with an exception",
     "Exception propagation from destructors is prohibited.",
     "Exceptions from destructors during stack unwinding call terminate()."),

    # --- Memory ---
    ("CPP2023-12.4.1", RuleCategory.MEMORY, Severity.REQUIRED,
     "Dynamic memory allocation shall not be used",
     "new/delete and malloc/free are prohibited in safety-critical code.",
     "Dynamic allocation has non-deterministic timing and can fail at runtime."),
    ("CPP2023-12.4.2", RuleCategory.MEMORY, Severity.ADVISORY,
     "Objects shall not be created with placement new unless in a memory pool",
     "Placement new shall only be used with pre-allocated memory pools.",
     "Ad-hoc placement new can cause alignment and lifetime errors."),

    # --- Identifiers ---
    ("CPP2023-5.3.1", RuleCategory.IDENTIFIERS, Severity.REQUIRED,
     "A name shall not shadow a name declared in an outer scope",
     "Identifier shadowing is prohibited.",
     "Shadowing causes confusion about which entity is referenced."),
    ("CPP2023-5.3.2", RuleCategory.IDENTIFIERS, Severity.ADVISORY,
     "Names introduced in a using-directive shall not conflict with any identifier in the same scope",
     "using namespace shall not introduce name conflicts.",
     "Conflicts create ambiguity."),

    # --- Error handling ---
    ("CPP2023-19.0.1", RuleCategory.ERROR_HANDLING, Severity.REQUIRED,
     "The error indicator errno shall not be used",
     "errno-based error reporting shall not be used.",
     "errno is not thread-safe and is easy to misuse."),
]


_PY2024_RULES_RAW: List[tuple] = [
    # --- Imports ---
    ("PY2024-1.1", RuleCategory.IMPORTS, Severity.REQUIRED,
     "Wildcard imports shall not be used",
     "'from module import *' is prohibited.",
     "Wildcard imports pollute the namespace and make dependencies implicit."),
    ("PY2024-1.2", RuleCategory.IMPORTS, Severity.ADVISORY,
     "Imports shall be grouped and ordered (stdlib, third-party, local)",
     "Imports shall follow the standard grouping convention.",
     "Consistent ordering makes dependencies easier to understand."),
    ("PY2024-1.3", RuleCategory.IMPORTS, Severity.REQUIRED,
     "Modules shall only be imported once per file",
     "Duplicate imports are prohibited.",
     "Duplicate imports indicate copy-paste errors."),

    # --- Naming ---
    ("PY2024-2.1", RuleCategory.NAMING_CONVENTIONS, Severity.REQUIRED,
     "Module and package names shall use lowercase_with_underscores",
     "Module names shall follow snake_case convention.",
     "PEP 8 naming improves readability and consistency."),
    ("PY2024-2.2", RuleCategory.NAMING_CONVENTIONS, Severity.REQUIRED,
     "Class names shall use CapWords convention",
     "Class names shall be in PascalCase.",
     "Consistent class naming helps distinguish types from functions/variables."),
    ("PY2024-2.3", RuleCategory.NAMING_CONVENTIONS, Severity.REQUIRED,
     "Function and variable names shall use lowercase_with_underscores",
     "Function and variable names shall follow snake_case.",
     "snake_case is the Python community standard."),
    ("PY2024-2.4", RuleCategory.NAMING_CONVENTIONS, Severity.REQUIRED,
     "Constants shall use UPPERCASE_WITH_UNDERSCORES",
     "Module-level constants shall be named in ALL_CAPS.",
     "Distinguishes constants from mutable variables."),
    ("PY2024-2.5", RuleCategory.NAMING_CONVENTIONS, Severity.ADVISORY,
     "Single-character variable names should be avoided except for loop counters",
     "Meaningful variable names shall be used.",
     "Single-character names obscure intent."),

    # --- Expressions ---
    ("PY2024-3.1", RuleCategory.EXPRESSIONS, Severity.REQUIRED,
     "Comparison to None shall use 'is' or 'is not', not == or !=",
     "'== None' and '!= None' are prohibited.",
     "'==' compares value not identity; None comparisons must use 'is'."),
    ("PY2024-3.2", RuleCategory.EXPRESSIONS, Severity.REQUIRED,
     "Comparison to True/False shall use 'is' or direct boolean test",
     "'== True' and '== False' are prohibited.",
     "Direct boolean tests are more Pythonic and correct."),
    ("PY2024-3.3", RuleCategory.EXPRESSIONS, Severity.ADVISORY,
     "The 'not in' and 'is not' operators shall be used instead of 'not x in' and 'not x is'",
     "Use 'not in' and 'is not' compound operators.",
     "Compound operators are clearer and avoid precedence issues."),
    ("PY2024-3.4", RuleCategory.EXPRESSIONS, Severity.REQUIRED,
     "The result of a function call shall not be silently discarded when the function signals errors via return value",
     "Return values that indicate errors shall not be discarded.",
     "Discarded error indicators cause silent failures."),

    # --- Control flow ---
    ("PY2024-4.1", RuleCategory.CONTROL_FLOW, Severity.REQUIRED,
     "All branches of a conditional shall be covered (no implicit pass-through)",
     "if-elif chains shall end with an else clause.",
     "Missing else may leave edge cases unhandled."),
    ("PY2024-4.2", RuleCategory.CONTROL_FLOW, Severity.ADVISORY,
     "Functions should have a single return statement where practical",
     "Prefer a single return point.",
     "Multiple returns complicate reasoning about postconditions."),
    ("PY2024-4.3", RuleCategory.CONTROL_FLOW, Severity.REQUIRED,
     "The 'continue' statement shall not be used in loops",
     "'continue' is prohibited.",
     "'continue' makes loop body logic harder to follow."),

    # --- Functions ---
    ("PY2024-5.1", RuleCategory.FUNCTIONS, Severity.REQUIRED,
     "Functions shall have type annotations for all parameters and return type",
     "All function parameters and return types shall be annotated.",
     "Type annotations enable static analysis and improve readability."),
    ("PY2024-5.2", RuleCategory.FUNCTIONS, Severity.REQUIRED,
     "Default mutable argument values shall not be used",
     "Mutable default arguments (list, dict, set) are prohibited.",
     "Mutable defaults are shared across all calls and cause subtle bugs."),
    ("PY2024-5.3", RuleCategory.FUNCTIONS, Severity.REQUIRED,
     "Functions shall not call themselves recursively",
     "Recursive functions are prohibited.",
     "Recursion can cause unbounded stack growth; use iteration."),
    ("PY2024-5.4", RuleCategory.FUNCTIONS, Severity.ADVISORY,
     "Functions shall not exceed 50 lines of code",
     "Functions longer than 50 lines should be refactored.",
     "Long functions are harder to understand and test."),
    ("PY2024-5.5", RuleCategory.FUNCTIONS, Severity.ADVISORY,
     "Functions shall not have more than 5 parameters",
     "Functions with more than 5 parameters should be refactored.",
     "Too many parameters indicate insufficient decomposition."),

    # --- Exceptions ---
    ("PY2024-6.1", RuleCategory.EXCEPTIONS, Severity.REQUIRED,
     "Bare 'except:' clauses shall not be used",
     "'except:' without an exception type is prohibited.",
     "Bare except catches SystemExit and KeyboardInterrupt unintentionally."),
    ("PY2024-6.2", RuleCategory.EXCEPTIONS, Severity.REQUIRED,
     "Exception variables in except clauses shall be used or explicitly ignored",
     "Caught exception objects shall be referenced or explicitly suppressed.",
     "Unused exception objects indicate missing error handling."),
    ("PY2024-6.3", RuleCategory.EXCEPTIONS, Severity.ADVISORY,
     "Empty except blocks shall not be used",
     "Except blocks shall not be empty (pass only).",
     "Empty except blocks silently suppress errors."),
    ("PY2024-6.4", RuleCategory.EXCEPTIONS, Severity.REQUIRED,
     "Exceptions shall be derived from Exception, not BaseException",
     "Custom exceptions shall inherit from Exception.",
     "BaseException includes SystemExit and KeyboardInterrupt."),

    # --- Complexity ---
    ("PY2024-7.1", RuleCategory.COMPLEXITY, Severity.ADVISORY,
     "Cyclomatic complexity of a function shall not exceed 10",
     "Functions shall have cyclomatic complexity ≤ 10.",
     "High complexity correlates with defect density."),
    ("PY2024-7.2", RuleCategory.COMPLEXITY, Severity.ADVISORY,
     "Nesting depth shall not exceed 4 levels",
     "Code nesting shall not exceed 4 levels.",
     "Deep nesting reduces readability."),

    # --- Language extensions / safety ---
    ("PY2024-8.1", RuleCategory.LANGUAGE_EXTENSIONS, Severity.REQUIRED,
     "eval() and exec() shall not be used",
     "Dynamic code execution via eval/exec is prohibited.",
     "eval/exec can execute arbitrary code and are a security hazard."),
    ("PY2024-8.2", RuleCategory.LANGUAGE_EXTENSIONS, Severity.REQUIRED,
     "Global variables shall not be modified from within a function using the 'global' statement",
     "'global' statement inside functions is prohibited.",
     "Global mutation makes programs hard to reason about and test."),
    ("PY2024-8.3", RuleCategory.LANGUAGE_EXTENSIONS, Severity.ADVISORY,
     "The 'assert' statement shall not be used in production code",
     "assert shall not be used for run-time checks in production.",
     "assert can be disabled with -O; use explicit if/raise instead."),
    ("PY2024-8.4", RuleCategory.LANGUAGE_EXTENSIONS, Severity.REQUIRED,
     "__import__() shall not be used directly",
     "Dynamic imports via __import__() are prohibited.",
     "Use importlib.import_module() instead."),
]


# ---------------------------------------------------------------------------
# Build RuleSpec objects
# ---------------------------------------------------------------------------

def _build_registry() -> Dict[str, RuleSpec]:
    registry: Dict[str, RuleSpec] = {}
    for raw_list, std in (
        (_C2012_RULES_RAW,   Standard.C2012),
        (_CPP2023_RULES_RAW, Standard.CPP2023),
        (_PY2024_RULES_RAW,  Standard.PY2024),
    ):
        for entry in raw_list:
            rule_id, cat, sev, title, desc, rationale = entry
            registry[rule_id] = RuleSpec(
                rule_id=rule_id,
                standard=std,
                category=cat,
                severity=sev,
                title=title,
                description=desc,
                rationale=rationale,
            )
    return registry


@lru_cache(maxsize=1)
def get_registry() -> Dict[str, RuleSpec]:
    """Return the shared rule registry (built once, cached)."""
    return _build_registry()


def get_rule(rule_id: str) -> Optional[RuleSpec]:
    return get_registry().get(rule_id)


def get_rules_for_standard(standard: Standard) -> List[RuleSpec]:
    return [r for r in get_registry().values() if r.standard == standard]
