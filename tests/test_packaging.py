"""Packaging metadata and README prerequisites / CLI reference (server segment)."""

import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())
PROJECT = PYPROJECT["project"]
DEPS = PROJECT["dependencies"]
README = (ROOT / "README.md").read_text()


def _dep(name):
    return next((d for d in DEPS if re.match(rf"{name}(\[|[<>=!~ ]|$)", d)), None)


# @spec SRV-034
def test_requires_python_311_or_later():
    assert PROJECT["requires-python"] == ">=3.11"


# @spec SRV-034
def test_requires_mcp_sdk_2_3_within_major_version_2():
    mcp = _dep("mcp")
    assert mcp is not None
    assert ">=2.3" in mcp and "<3" in mcp


# @spec SRV-029
def test_ghidrecomp_is_an_optional_extra():
    assert _dep("ghidrecomp") is None
    extras = PROJECT.get("optional-dependencies", {})
    assert any(any(d.startswith("ghidrecomp") for d in group) for group in extras.values())


# @spec SRV-040
def test_direct_dependencies_and_single_sourced_version():
    assert _dep("pydantic") is not None
    assert _dep("jpype1") is not None
    assert "version" not in PROJECT
    assert "version" in PROJECT.get("dynamic", [])


# @spec SRV-034
def test_readme_states_the_platform_prerequisites():
    assert "Ghidra 12.1" in README
    assert "JDK 21" in README
    assert "Python 3.11" in README and "3.14" in README
    assert "11.1–11.3" not in README
    assert "JDK 17" not in README
    # Example paths and commands use the supported versions too.
    assert "ghidra_11." not in README
    assert "java-17" not in README


# @spec SRV-041
def test_readme_cli_reference_matches_the_cli():
    options_table = README.split("## CLI Reference", 1)[1].split("## Tool Reference", 1)[0]
    assert "`sse`" not in options_table
    assert "--analyze-only" in options_table
    wait_row = next(line for line in options_table.splitlines() if "--wait-for-analysis" in line)
    assert "45" in wait_row and "on" in wait_row
    for removed in ("--force-analysis", "--no-symbols", "--sym-file-path", "--gdt", "--program-options"):
        assert removed not in options_table, removed


# @spec SRV-001, SRV-030
def test_console_script_and_module_entry_points():
    assert PROJECT["scripts"]["ghidra-mcp"] == "ghidra_mcp.server:main"
    result = subprocess.run(
        [sys.executable, "-m", "ghidra_mcp", "--version"], capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, result.stderr
    from ghidra_mcp import __version__

    assert __version__ in result.stdout
