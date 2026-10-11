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


def _section(heading: str) -> str:
    return README.split(heading, 1)[1].split("\n## ", 1)[0]


def _mise() -> dict:
    return tomllib.loads((ROOT / "mise.toml").read_text())


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
    prerequisites = _section("## Prerequisites")
    assert "mise" in prerequisites and "Ghidra 12.1" in prerequisites and "JDK 21" in prerequisites
    assert "Python 3.13" in prerequisites
    assert "3.11" in prerequisites and "3.14" in prerequisites
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


# @spec GUI-022
def test_readme_documents_gui_mode_and_its_analysis_blind_spot():
    assert "--gui" in README
    section = README.split("## GUI Mode", 1)[1].split("\n## ", 1)[0]
    assert "analyzer failures" in section and "ready" in section


# @spec SRV-046
def test_mise_provides_python_and_a_project_venv_and_requires_ghidra_and_jdk_paths():
    mise = _mise()
    assert mise["tools"] == {"python": "3.13"}  # Ghidra and the JDK are paths, not mise tools
    env = mise["env"]
    # uv (which mise uses when installed) leaves pip out of new venvs unless asked to seed it
    assert env["_"]["python"]["venv"] == {"path": ".venv", "create": True, "uv_create_args": ["--seed"]}
    for var in ("GHIDRA_INSTALL_DIR", "JAVA_HOME"):
        assert "mise.local.toml" in env[var]["required"]


# @spec SRV-047
def test_mise_tasks_install_test_and_serve():
    tasks = _mise()["tasks"]
    assert tasks["install"]["run"] == 'python -m pip install -e ".[ghidrecomp,dev]"'  # the venv's own pip
    assert tasks["test"]["run"] == 'pytest -m "not integration"'
    assert tasks["test:integration"]["run"] == "pytest -m integration"
    assert tasks["test:gui"]["run"] == "pytest -m gui"
    assert tasks["test:gui"]["env"] == {"GHIDRA_MCP_GUI_TESTS": "1"}
    assert tasks["serve"]["run"] == "ghidra-mcp"
    assert tasks["gui"]["run"] == "ghidra-mcp --gui"
    # raw: mise delivers Ctrl+C once and lets the server finish closing the project
    assert tasks["serve"]["raw"] is True and tasks["gui"]["raw"] is True


# @spec SRV-048
def test_local_paths_come_from_an_ignored_mise_local_toml():
    example = tomllib.loads((ROOT / "mise.local.toml.example").read_text())
    assert {"GHIDRA_INSTALL_DIR", "JAVA_HOME"} <= set(example["env"])
    assert "mise.local.toml" in (ROOT / ".gitignore").read_text().split()


# @spec SRV-049
def test_readme_installs_with_mise_only_and_clients_launch_through_mise():
    install = _section("## Installation")
    for step in ("mise.local.toml", "mise trust", "mise install", "mise run install"):
        assert step in install, step
    assert "pip install" not in install
    clients = _section("## MCP Client Configuration")
    assert "mise exec -C" in clients and '"command": "mise"' in clients
    assert '"command": "ghidra-mcp"' not in README
    assert '"GHIDRA_INSTALL_DIR"' not in clients  # the paths come from mise.local.toml
