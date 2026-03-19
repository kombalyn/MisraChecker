"""
misra-checker – MISRA C:2012 / C++:2023 / Python:2024 compliance checker.

Install:
    pip install .                          # core only (all standards included)
    pip install ".[agent]"                 # + LangChain integration
    pip install ".[server]"                # + Flask API
    pip install ".[dev]"                   # + test/lint tools
    pip install ".[all]"                   # everything
"""

from setuptools import setup, find_packages

setup(
    name="misra-checker",
    version="1.0.0",
    author="Your Name",
    description="MISRA C:2012 / C++:2023 / Python:2024 compliance checker – hybrid AST + regex",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/YOUR_ORG/misra-checker",
    packages=find_packages(exclude=["tests*", "docs*", "examples*"]),
    python_requires=">=3.10",
    install_requires=[
        # No mandatory third-party deps – stdlib only for core engine
    ],
    extras_require={
        # Integration with the Programozó Ágens project
        "agent": [
            "langchain-core>=0.3.0",
        ],
        # HTTP API endpoint
        "server": [
            "flask>=3.0.0",
            "flask-cors>=4.0.0",
        ],
        # Development / CI
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "ruff>=0.4.0",
            "mypy>=1.0.0",
        ],
        # Everything
        "all": [
            "langchain-core>=0.3.0",
            "flask>=3.0.0",
            "flask-cors>=4.0.0",
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "ruff>=0.4.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "misra-checker=misra_checker.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="misra compliance static-analysis c cpp python safety automotive embedded",
)
