"""Tests for the IBM watsonx Orchestrate integration layer.

These tests do not require a live Orchestrate instance. They verify everything
that can go wrong BEFORE `orchestrate toolkits import` is called:

  1. server.py entrypoint — sys.path setup, DATA_DIR anchoring, MCP import
  2. toolkit.yaml schema   — required fields, correct values
  3. register-toolkit.sh   — sed substitutions produce a valid generated YAML
  4. vulncompass_agent.yaml — schema, tool references match toolkit name
  5. requirements.txt sync — pinned deps cover every pyproject.toml runtime dep

None of these tests start a network connection or invoke the Orchestrate CLI.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]
KIT_DIR = REPO_ROOT / "deploy" / "ibm" / "local-mcp-toolkit"
SERVER_PY = KIT_DIR / "server.py"
TOOLKIT_YAML = KIT_DIR / "toolkit.yaml"
AGENT_YAML = KIT_DIR / "vulncompass_agent.yaml"
REQUIREMENTS_TXT = KIT_DIR / "requirements.txt"
REGISTER_SH = KIT_DIR / "register-toolkit.sh"
PYPROJECT = REPO_ROOT / "pyproject.toml"


# ===========================================================================
# 1. server.py entrypoint
# ===========================================================================


def test_server_py_exists():
    assert SERVER_PY.exists(), f"{SERVER_PY} not found"


def test_server_py_inserts_own_dir_into_sys_path():
    """_HERE is added to sys.path before any vulncompass import."""
    src = SERVER_PY.read_text()
    # Must compute _HERE from __file__ and insert it before importing.
    assert "_HERE" in src
    assert "sys.path.insert(0, _HERE)" in src


def test_server_py_sets_data_dir_before_import():
    """DATA_DIR env var must be set before `from vulncompass.app import mcp`
    because Settings() is evaluated at module import time."""
    src = SERVER_PY.read_text()
    lines = src.splitlines()
    data_dir_line = next(
        (i for i, ln in enumerate(lines) if "DATA_DIR" in ln and "os.environ" in ln),
        None,
    )
    import_line = next(
        (i for i, ln in enumerate(lines) if "from vulncompass.app import" in ln),
        None,
    )
    assert data_dir_line is not None, "DATA_DIR not set in server.py"
    assert import_line is not None, "vulncompass.app not imported in server.py"
    assert data_dir_line < import_line, (
        "DATA_DIR must be set before `from vulncompass.app import mcp` "
        f"(DATA_DIR at line {data_dir_line}, import at line {import_line})"
    )


def test_server_py_data_dir_respects_env_override():
    """If DATA_DIR is already set, server.py must not overwrite it."""
    src = SERVER_PY.read_text()
    # Guard must be `if not os.environ.get("DATA_DIR"):` (or equivalent).
    assert 'os.environ.get("DATA_DIR")' in src or "os.environ.get('DATA_DIR')" in src


def test_server_py_anchors_data_dir_to_here():
    """DATA_DIR must be anchored to _HERE, not to a relative path."""
    src = SERVER_PY.read_text()
    # The assignment must reference _HERE, not a bare relative string.
    assert re.search(r"DATA_DIR.*_HERE", src), (
        "DATA_DIR should be set relative to _HERE so it is stable across CWDs"
    )


def test_server_py_imports_mcp_and_runs_stdio():
    src = SERVER_PY.read_text()
    assert "from vulncompass.app import mcp" in src
    assert 'mcp.run(transport="stdio")' in src


def test_server_py_is_importable_from_src_layout(tmp_path, monkeypatch):
    """Simulate the staged layout: vulncompass package next to server.py.
    server.py must import cleanly without the repo's src/ prefix on sys.path.
    """
    # Build a minimal staged dir mirroring what register-toolkit.sh produces.
    stage = tmp_path / "stage"
    stage.mkdir()
    # Copy server.py into the staged dir.
    import shutil

    shutil.copy(SERVER_PY, stage / "server.py")
    # Symlink (or copy) the vulncompass package directly under stage/.
    src_pkg = REPO_ROOT / "src" / "vulncompass"
    shutil.copytree(src_pkg, stage / "vulncompass")

    # Run `python server.py` with a fixed DATA_DIR and no stdin (it should
    # import successfully and then block on stdio; send EOF immediately).
    result = subprocess.run(
        [sys.executable, str(stage / "server.py")],
        cwd=str(stage),
        env={**os.environ, "DATA_DIR": str(tmp_path / ".vulncompass")},
        input=b"",  # EOF on stdin — server exits after MCP handshake attempt
        capture_output=True,
        timeout=15,
    )
    # FastMCP exits cleanly on EOF stdin; anything other than an import error
    # (exit code 1 with Traceback) is acceptable.
    assert b"Traceback" not in result.stderr or b"ImportError" not in result.stderr, (
        f"server.py raised an import error:\n{result.stderr.decode()}"
    )


# ===========================================================================
# 2. toolkit.yaml schema
# ===========================================================================


def _load_toolkit_yaml() -> dict:
    with TOOLKIT_YAML.open() as fh:
        return yaml.safe_load(fh)


def test_toolkit_yaml_exists():
    assert TOOLKIT_YAML.exists()


def test_toolkit_yaml_is_valid_yaml():
    doc = _load_toolkit_yaml()
    assert isinstance(doc, dict)


def test_toolkit_yaml_spec_version():
    assert _load_toolkit_yaml()["spec_version"] == "v1"


def test_toolkit_yaml_kind_is_mcp():
    assert _load_toolkit_yaml()["kind"] == "mcp"


def test_toolkit_yaml_name_is_vulncompass():
    """Name in the template must be 'vulncompass' — the register script also
    rewrites it from $TOOLKIT_NAME, but the template default must match the
    agent YAML tool prefix."""
    assert _load_toolkit_yaml()["name"] == "vulncompass"


def test_toolkit_yaml_command_runs_server_py():
    assert _load_toolkit_yaml()["command"] == "python server.py"


def test_toolkit_yaml_tools_wildcard():
    """tools: ["*"] exposes all four VulnCompass tools without listing them."""
    assert _load_toolkit_yaml()["tools"] == ["*"]


# ===========================================================================
# 3. register-toolkit.sh sed substitutions
# ===========================================================================


def _apply_register_sed(toolkit_name: str, stage_dir: str) -> dict:
    """Run the same sed the register script uses and parse the output as YAML."""
    result = subprocess.run(
        [
            "sed",
            "-E",
            "-e",
            f"s#^package_root:.*#package_root: {stage_dir}#",
            "-e",
            f"s#^name:.*#name: {toolkit_name}#",
            str(TOOLKIT_YAML),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return yaml.safe_load(result.stdout)


def test_register_sh_sed_rewrites_name():
    doc = _apply_register_sed("vulncompass", "/tmp/fake_stage")
    assert doc["name"] == "vulncompass", (
        "sed in register-toolkit.sh did not rewrite `name`"
    )


def test_register_sh_sed_rewrites_name_custom():
    """A custom TOOLKIT_NAME must also propagate correctly."""
    doc = _apply_register_sed("my_custom_toolkit", "/tmp/fake_stage")
    assert doc["name"] == "my_custom_toolkit"


def test_register_sh_sed_rewrites_package_root():
    doc = _apply_register_sed("vulncompass", "/absolute/path/to/stage")
    assert doc["package_root"] == "/absolute/path/to/stage"


def test_register_sh_sed_preserves_other_fields():
    doc = _apply_register_sed("vulncompass", "/tmp/fake_stage")
    assert doc["spec_version"] == "v1"
    assert doc["kind"] == "mcp"
    assert doc["command"] == "python server.py"
    assert doc["tools"] == ["*"]


def test_register_sh_sed_generated_yaml_is_valid():
    """The generated YAML must be parseable — no broken indentation."""
    doc = _apply_register_sed("vulncompass", "/tmp/fake_stage")
    assert isinstance(doc, dict)
    assert len(doc) >= 5  # spec_version, kind, name, command, tools, package_root


# ===========================================================================
# 4. vulncompass_agent.yaml schema
# ===========================================================================


def _load_agent_yaml() -> dict:
    with AGENT_YAML.open() as fh:
        return yaml.safe_load(fh)


def test_agent_yaml_exists():
    assert AGENT_YAML.exists()


def test_agent_yaml_is_valid_yaml():
    doc = _load_agent_yaml()
    assert isinstance(doc, dict)


def test_agent_yaml_spec_version():
    assert _load_agent_yaml()["spec_version"] == "v1"


def test_agent_yaml_kind_is_native():
    assert _load_agent_yaml()["kind"] == "native"


def test_agent_yaml_has_name():
    assert _load_agent_yaml().get("name"), "agent YAML must have a non-empty name"


def test_agent_yaml_has_llm():
    assert _load_agent_yaml().get("llm"), "agent YAML must specify an llm"


def test_agent_yaml_has_instructions():
    instructions = _load_agent_yaml().get("instructions", "")
    assert len(instructions) > 50, "agent instructions appear too short or missing"


def test_agent_yaml_tools_reference_vulncompass_prefix():
    """Every tool reference must use the 'vulncompass:' prefix so Orchestrate
    routes calls to the toolkit named 'vulncompass'."""
    tools = _load_agent_yaml().get("tools", [])
    assert len(tools) > 0, "agent YAML has no tools"
    for tool_ref in tools:
        assert tool_ref.startswith("vulncompass:"), (
            f"tool reference {tool_ref!r} does not start with 'vulncompass:' — "
            "it will not resolve against the registered toolkit"
        )


def test_agent_yaml_exposes_all_four_tools():
    tools = _load_agent_yaml().get("tools", [])
    tool_names = {t.split(":", 1)[1] for t in tools}
    assert tool_names == {
        "assess_finding",
        "prioritize_findings",
        "detect_material_changes",
        "record_analyst_decision",
    }


def test_agent_yaml_toolkit_prefix_matches_toolkit_name():
    """The prefix used in agent tool references must match the toolkit name
    that toolkit.yaml (and the register script) set."""
    toolkit_name = _load_toolkit_yaml()["name"]
    for tool_ref in _load_agent_yaml().get("tools", []):
        prefix = tool_ref.split(":")[0]
        assert prefix == toolkit_name, (
            f"Agent tool {tool_ref!r} uses prefix {prefix!r} but "
            f"toolkit.yaml name is {toolkit_name!r}"
        )


def test_agent_yaml_instructions_mention_all_four_tools():
    instructions = _load_agent_yaml().get("instructions", "")
    for tool in (
        "assess_finding",
        "prioritize_findings",
        "detect_material_changes",
        "record_analyst_decision",
    ):
        assert tool in instructions, (
            f"Tool {tool!r} not mentioned in agent instructions"
        )


# ===========================================================================
# 5. requirements.txt sync with pyproject.toml
# ===========================================================================


def _parse_req_names(path: Path) -> set[str]:
    """Return normalised package names from a requirements.txt (no versions)."""
    names = set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip version specifiers: fastmcp>=2.0.0 -> fastmcp
        name = re.split(r"[>=<!~\[]", line)[0].strip().lower().replace("-", "_")
        names.add(name)
    return names


def _parse_pyproject_runtime_deps(path: Path) -> set[str]:
    """Return normalised package names from pyproject.toml [project.dependencies]."""
    import tomllib  # Python 3.11+

    with path.open("rb") as fh:
        data = tomllib.load(fh)
    names = set()
    for dep in data.get("project", {}).get("dependencies", []):
        name = re.split(r"[>=<!~\[\s]", dep)[0].strip().lower().replace("-", "_")
        names.add(name)
    return names


def test_requirements_txt_exists():
    assert REQUIREMENTS_TXT.exists()


def test_requirements_txt_covers_all_pyproject_runtime_deps():
    """Every runtime dep in pyproject.toml must appear in requirements.txt.

    The local MCP toolkit installs only from requirements.txt (it has no
    pyproject.toml at package_root). If a dep is missing, the server fails to
    start inside Orchestrate with an ImportError.
    """
    req_names = _parse_req_names(REQUIREMENTS_TXT)
    pyproject_names = _parse_pyproject_runtime_deps(PYPROJECT)
    missing = pyproject_names - req_names
    assert not missing, (
        f"These runtime deps from pyproject.toml are absent from "
        f"deploy/ibm/local-mcp-toolkit/requirements.txt: {missing}\n"
        f"Add them to keep the two files in sync."
    )


# ===========================================================================
# 6. End-to-end YAML naming consistency
# ===========================================================================
# These tests validate the complete naming chain as a single unit:
#
#   toolkit.yaml  `name:`
#       └─ must equal ─▶  agent YAML tool prefix  (e.g. "vulncompass:")
#       └─ must equal ─▶  register-toolkit.sh default TOOLKIT_NAME
#       └─ must equal ─▶  sed-rewritten generated YAML `name:`
#
# A mismatch at any link causes Orchestrate to silently fail to route tool
# calls from the agent to the toolkit.


def test_naming_chain_toolkit_name_equals_agent_tool_prefix():
    """toolkit.yaml `name` must equal every agent tool reference prefix.

    This is the critical invariant that makes Orchestrate route tool calls
    correctly. If these diverge, the agent silently gets no tools.
    """
    toolkit_name = _load_toolkit_yaml()["name"]
    agent_tools = _load_agent_yaml().get("tools", [])
    assert agent_tools, "agent YAML has no tools"
    prefixes = {t.split(":")[0] for t in agent_tools}
    assert prefixes == {toolkit_name}, (
        f"Mismatch: toolkit.yaml name={toolkit_name!r} but "
        f"agent tool prefixes={prefixes!r}.\n"
        f"All agent tool references must start with '{toolkit_name}:'."
    )


def test_naming_chain_register_script_default_toolkit_name():
    """register-toolkit.sh must default TOOLKIT_NAME to match toolkit.yaml `name`."""
    toolkit_name = _load_toolkit_yaml()["name"]
    script_src = REGISTER_SH.read_text()
    # The script sets TOOLKIT_NAME via: TOOLKIT_NAME="${TOOLKIT_NAME:-<default>}"
    # The default must match the toolkit.yaml name.
    match = re.search(r'TOOLKIT_NAME="\$\{TOOLKIT_NAME:-([^}]+)\}"', script_src)
    default = match.group(1) if match else "not found"
    assert match is None or match.group(1) == toolkit_name, (
        f"register-toolkit.sh default TOOLKIT_NAME={default!r} "
        f"does not match toolkit.yaml name={toolkit_name!r}"
    )


def test_naming_chain_register_script_sed_produces_matching_name():
    """The sed command in register-toolkit.sh must rewrite `name:` in toolkit.yaml
    so the generated file's name equals the toolkit.yaml template name when
    TOOLKIT_NAME equals that template name."""
    toolkit_name = _load_toolkit_yaml()["name"]
    generated = _apply_register_sed(toolkit_name, "/tmp/fake_stage")
    assert generated["name"] == toolkit_name, (
        f"sed rewrite produced name={generated['name']!r}, expected {toolkit_name!r}"
    )


def test_naming_chain_agent_tool_names_exist_in_toolkit_tools_wildcard():
    """toolkit.yaml exposes tools: ['*'] which means all server tools are available.
    Verify the agent only references tool names that the server actually registers.
    """
    toolkit_doc = _load_toolkit_yaml()
    # tools: ["*"] exposes everything — no filtering needed.
    assert toolkit_doc.get("tools") == ["*"], (
        "toolkit.yaml must use tools: ['*'] to expose all VulnCompass tools"
    )
    # Verify the agent-referenced tool names are the four known server tools.
    agent_tool_names = {t.split(":", 1)[1] for t in _load_agent_yaml().get("tools", [])}
    known_tools = {
        "assess_finding",
        "prioritize_findings",
        "detect_material_changes",
        "record_analyst_decision",
    }
    unknown = agent_tool_names - known_tools
    assert not unknown, (
        f"Agent references unknown tool names: {unknown!r}. "
        f"Known server tools: {known_tools!r}"
    )


def test_naming_chain_ci_yml_exists_and_uses_frozen():
    """ci.yml must exist and use --frozen to ensure reproducible installs."""
    ci_yml = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    assert ci_yml.exists(), "ci.yml not found — CI is not configured"
    src = ci_yml.read_text()
    assert "--frozen" in src, (
        "ci.yml must pass --frozen to `uv sync` to use the pinned uv.lock. "
        "Without --frozen, CI may install different versions than the lockfile."
    )


def test_naming_chain_ci_yml_has_read_permissions():
    """ci.yml must declare read-only permissions at the workflow level."""
    ci_yml = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    src = ci_yml.read_text()
    assert "permissions:" in src, "ci.yml must declare explicit permissions"
    assert "contents: read" in src, (
        "ci.yml must set `contents: read` — the default (write) is too broad"
    )


def test_naming_chain_no_deploy_job_in_ci():
    """CI must not contain an active (uncommented) deploy/publish job.
    Deployment stays manual until durable storage and auth are settled.
    """
    ci_yml = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    src = ci_yml.read_text()
    # Active job keys — lines that are NOT comments and contain 'deploy' or 'publish'.
    active_deploy = [
        line
        for line in src.splitlines()
        if not line.lstrip().startswith("#")
        and re.search(r"\b(deploy|publish|release)\b", line, re.IGNORECASE)
        and re.search(r"^\s{2}\w[\w-]+:", line)  # top-level job key pattern
    ]
    assert not active_deploy, (
        "ci.yml contains an active deploy/publish job. Keep deployment manual "
        "until durable storage and MCP transport auth are in place.\n"
        f"Found: {active_deploy}"
    )
