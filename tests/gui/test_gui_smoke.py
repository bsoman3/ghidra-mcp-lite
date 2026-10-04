"""GUI smoke suite: runs `ghidra-mcp --gui` for real and drives it over HTTP.

Needs GHIDRA_INSTALL_DIR, a display, a C compiler, and GHIDRA_MCP_GUI_TESTS=1. A Ghidra
window appears while it runs; Ghidra uses an isolated settings directory.
"""

import getpass
import os
import shutil
import socket
import subprocess
import sys
import time

import pytest
from mcp import Client

pytestmark = [pytest.mark.gui, pytest.mark.integration]

SOURCE = "int add(int a, int b) { return a + b; }\nint main(void) { return add(1, 2); }\n"


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _settings(root):
    for folder in ("ghidra", f"{getpass.getuser()}-ghidra"):
        prefs = root / folder / "ghidra_12.1.4_PUBLIC"
        prefs.mkdir(parents=True, exist_ok=True)
        (prefs / "preferences").write_text("USER_AGREEMENT=ACCEPT\nSHOW_TIPS=false\n")


@pytest.fixture(scope="module")
def gui_server(tmp_path_factory):
    if shutil.which("cc") is None:
        pytest.skip("needs a C compiler (cc)")
    work = tmp_path_factory.mktemp("gui")
    (work / "hello.c").write_text(SOURCE)
    subprocess.run(["cc", "-O0", "-o", str(work / "hello"), str(work / "hello.c")], check=True)
    _settings(work / "settings")
    env = dict(os.environ, JAVA_TOOL_OPTIONS=f"-Dapplication.settingsdir={work / 'settings'}")
    port = _free_port()
    log = (work / "server.log").open("w")
    proc = subprocess.Popen(
        [sys.executable, "-m", "ghidra_mcp", "--gui", "--port", str(port),
         "--project-path", str(work / "proj"), "--project-name", "smoke", str(work / "hello")],
        env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                break
        if proc.poll() is not None:
            pytest.fail(f"ghidra-mcp --gui exited early; see {work / 'server.log'}")
        time.sleep(1)
    else:
        proc.kill()
        pytest.fail(f"ghidra-mcp --gui did not start serving; see {work / 'server.log'}")
    yield port
    proc.terminate()
    try:
        proc.wait(20)
    except subprocess.TimeoutExpired:
        proc.kill()


def _text(result):
    return "".join(getattr(block, "text", "") for block in result.content)


# @spec GUI-005, GUI-013, GUI-014, GUI-017, GUI-019, GUI-023, GUI-025, GUI-027, GUI-028, GUI-030
@pytest.mark.anyio
async def test_gui_mode_end_to_end(gui_server):
    async with Client(f"http://127.0.0.1:{gui_server}/mcp") as client:
        name, deadline = None, time.monotonic() + 240
        while time.monotonic() < deadline:
            listing = (await client.call_tool("list_project_binaries", {})).structured_content
            rows = [p for p in listing["programs"] if p["name"].startswith("hello-")]
            if rows and rows[0]["status"] in ("ready", "failed"):
                assert rows[0]["status"] == "ready", rows[0]
                name = rows[0]["name"]
                break
            time.sleep(1)
        assert name, "hello was not analyzed in time"

        functions = (await client.call_tool("list_functions", {"binary_name": name, "query": "add"})).structured_content
        add = next(f for f in functions["functions"] if f["name"].lstrip("_") == "add")
        renamed = await client.call_tool("rename_function_by_address", {
            "binary_name": name, "address": add["address"], "new_name": "gui_add"})
        assert not renamed.is_error and "not saved" in _text(renamed), _text(renamed)
        decompiled = await client.call_tool("decompile_function", {"binary_name": name, "name_or_address": "gui_add"})
        assert "gui_add" in decompiled.structured_content["signature"]

        moved = await client.call_tool("go_to", {"binary_name": name, "name_or_address": "gui_add"})
        assert not moved.is_error, _text(moved)
        where = (await client.call_tool("get_current_address", {})).structured_content
        assert where["binary_name"] == name and where["address"] == add["address"]
        current = (await client.call_tool("get_current_function", {})).structured_content
        assert current["function"]["name"] == "gui_add"
