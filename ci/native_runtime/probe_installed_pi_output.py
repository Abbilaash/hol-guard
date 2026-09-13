"""Exercise the installed Pi/OMP extension against the native hook CLI.

The native-wheel workflow already builds and installs the wheel. This probe
only checks the generated extension boundary: successful cases use the real
installed CLI, while the negative cases deliberately inject malformed CLI
results to prove the extension remains fail-closed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TEXT_LIMIT = 12_000
_ENV_ALLOWLIST = {
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMPDIR",
    "USERPROFILE",
}


class ProbeError(RuntimeError):
    """Raised when the installed Pi/native boundary cannot be proven."""


def _is_source_checkout_package(package_path: Path, repo_root: Path) -> bool:
    return package_path.is_relative_to((repo_root / "src" / "codex_plugin_scanner").resolve())


def _installed_package_path(repo_root: Path) -> Path:
    package = importlib.import_module("codex_plugin_scanner")
    raw_path = getattr(package, "__file__", None)
    if not isinstance(raw_path, str) or not raw_path:
        raise ProbeError("installed package origin is unavailable")
    package_path = Path(raw_path).resolve()
    if _is_source_checkout_package(package_path, repo_root):
        raise ProbeError(f"probe imported source tree package: {package_path}")
    return package_path


def _short_temp_parent() -> str | None:
    candidate = Path("/tmp")
    if candidate.is_dir() and os.access(candidate, os.W_OK | os.X_OK):
        return str(candidate)
    return None


def _short(value: bytes | str, limit: int = 1_500) -> str:
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
    return text if len(text) <= limit else text[:limit] + "..."


def _run(
    argv: list[str],
    *,
    env: Mapping[str, str],
    cwd: Path,
    timeout: float,
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=dict(env),
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeError(f"{label} did not complete: {exc}") from exc
    if completed.returncode != 0:
        raise ProbeError(
            f"{label} failed with exit {completed.returncode}: "
            f"stdout={_short(completed.stdout)!r} stderr={_short(completed.stderr)!r}"
        )
    return completed


def _isolated_env(*, home: Path, python_path: Path) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key in _ENV_ALLOWLIST}
    bin_dir = home / ".local" / "bin"
    env["PATH"] = os.pathsep.join((str(bin_dir), str(python_path.parent), env.get("PATH", "")))
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    env["XDG_CONFIG_HOME"] = str(home / "config")
    env["XDG_CACHE_HOME"] = str(home / "cache")
    env["XDG_DATA_HOME"] = str(home / "data")
    env["XDG_STATE_HOME"] = str(home / "state")
    env.pop("PYTHONPATH", None)
    for key in tuple(os.environ):
        if key.startswith("HOL_GUARD_") or key.startswith("GUARD_"):
            env.pop(key, None)
    return env


def _node_command() -> list[str]:
    node = shutil.which("node")
    if not node:
        raise ProbeError("Node is required for the generated Pi extension probe")
    help_result = subprocess.run([node, "--help"], capture_output=True, text=True, check=False)
    if help_result.returncode != 0 or "--experimental-strip-types" not in help_result.stdout:
        raise ProbeError("Node with --experimental-strip-types is required")
    return [node, "--no-warnings", "--experimental-strip-types"]


def _cases() -> list[dict[str, Any]]:
    return [
        {"id": "small", "content": [{"type": "text", "text": "const value = 1;\r\n"}]},
        {"id": "empty", "content": []},
        {
            "id": "multiblock-crlf-unicode",
            "content": [
                {"type": "text", "text": "first line\r\n"},
                {"type": "metadata", "value": "ignored"},
                {"type": "text", "text": "second line: \U0001f600\n"},
            ],
        },
        {"id": "large-nonsource", "content": [{"type": "text", "text": "safe\r\n" * 2_500}]},
    ]


def _negative_cases() -> list[dict[str, Any]]:
    return [
        {"id": "negative-empty", "content": [{"type": "text", "text": "safe"}]},
        {"id": "negative-malformed", "content": [{"type": "text", "text": "safe"}]},
        {"id": "negative-missing-decision", "content": [{"type": "text", "text": "safe"}]},
        {"id": "negative-missing-proof", "content": [{"type": "text", "text": "safe"}]},
        {"id": "negative-mismatch-proof", "content": [{"type": "text", "text": "safe"}]},
        {"id": "negative-nonzero-allow", "content": [{"type": "text", "text": "safe"}]},
        {"id": "negative-observe", "content": [{"type": "text", "text": "record only"}]},
    ]


def _text_digest(content: list[dict[str, Any]]) -> tuple[str, int, str]:
    text = "".join(item["text"] for item in content if item.get("type") == "text" and isinstance(item.get("text"), str))
    return hashlib.sha256(text.encode("utf-8")).hexdigest(), len(text), text[:_TEXT_LIMIT]


def _write_cli_wrapper(path: Path, *, python_path: Path, log_path: Path, negative: bool) -> None:
    source = f"""\
#!/usr/bin/env python3
import base64
import json
import os
import subprocess
import sys

PYTHON = {str(python_path)!r}
LOG = {str(log_path)!r}

def record(payload):
    with open(LOG, "ab") as handle:
        handle.write(json.dumps(payload, sort_keys=True).encode("utf-8") + b"\\n")

stdin_bytes = sys.stdin.buffer.read()
try:
    request = json.loads(stdin_bytes.decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError):
    request = {{}}
case_id = request.get("tool_call_id") if isinstance(request, dict) else None
if not isinstance(case_id, str):
    case_id = "unknown"
if {negative!s}:
    mismatch = "0" * 64
    responses = {{
        "negative-empty": (0, b"", b""),
        "negative-malformed": (0, b"not-json\\n", b""),
        "negative-missing-decision": (0, b'{{"policy_action":"allow"}}\\n', b""),
        "negative-missing-proof": (0, b'{{"decision":"allow","model_output_action":"allow_original"}}\\n', b""),
        "negative-mismatch-proof": (
            0,
            b'{{"decision":"allow","model_output_action":"allow_original","reviewed_output_sha256":"'
            + mismatch.encode()
            + b'"}}\\n',
            b"",
        ),
        "negative-nonzero-allow": (2, b'{{"decision":"allow"}}\\n', b"cli failed\\n"),
        "negative-observe": (0, b'{{"decision":"allow","observe_mode":true}}\\n', b""),
    }}
    returncode, stdout, stderr = responses.get(case_id, responses["negative-malformed"])
else:
    child_env = dict(os.environ)
    child_env.pop("PYTHONPATH", None)
    child_env["PYTHONNOUSERSITE"] = "1"
    try:
        completed = subprocess.run(
            [PYTHON, "-m", "codex_plugin_scanner.cli", *sys.argv[1:]],
            input=stdin_bytes,
            capture_output=True,
            check=False,
            env=child_env,
        )
        returncode, stdout, stderr = completed.returncode, completed.stdout, completed.stderr
    except OSError as exc:
        returncode, stdout, stderr = 127, b"", str(exc).encode("utf-8", errors="replace")
record({{
    "case_id": case_id,
    "returncode": returncode,
    "stdin_b64": base64.b64encode(stdin_bytes).decode("ascii"),
    "stdout_b64": base64.b64encode(stdout).decode("ascii"),
    "stderr_b64": base64.b64encode(stderr).decode("ascii"),
}})
sys.stdout.buffer.write(stdout)
sys.stderr.buffer.write(stderr)
sys.exit(returncode)
"""
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    path.chmod(0o700)


def _write_node_runner(path: Path) -> None:
    path.write_text(
        """\
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const extensionPath = process.argv[2];
const casesPath = process.argv[3];
const cwd = process.argv[4];
const extensionModule = await import(pathToFileURL(extensionPath).href);
const handlers = new Map();
const notifications = [];
const pi = {
  on(name, handler) { handlers.set(name, handler); },
  sendMessage(...args) { notifications.push({ kind: "sendMessage", args }); },
};
extensionModule.default(pi);
const handler = handlers.get("tool_result");
if (typeof handler !== "function") throw new Error("generated extension did not register tool_result");
const cases = JSON.parse(readFileSync(casesPath, "utf8"));
const results = [];
for (const testCase of cases) {
  const before = notifications.length;
  const result = await handler(
    {
      toolCallId: testCase.id,
      toolName: "Bash",
      content: testCase.content,
      details: { probe: testCase.id },
      isError: false,
    },
    { cwd, ui: { notify(message, kind) { notifications.push({ message, kind }); } } },
  );
  results.push({
    id: testCase.id,
    preserved: result === undefined,
    result: result === undefined ? null : result,
    notifications: notifications.slice(before),
  });
}
process.stdout.write(JSON.stringify({ results }));
""",
        encoding="utf-8",
    )


def _generate_extension(
    path: Path,
    *,
    guard_home: Path,
    home: Path,
    settings_path: Path,
) -> None:
    from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source

    path.write_text(
        managed_extension_source(
            guard_home=guard_home,
            home_dir=home,
            settings_path=settings_path,
            harness="omp",
            display_name="Oh My Pi",
        ),
        encoding="utf-8",
    )


def _run_node_cases(
    *,
    node: list[str],
    extension: Path,
    runner: Path,
    cases: Path,
    cwd: Path,
    env: Mapping[str, str],
) -> list[dict[str, Any]]:
    completed = _run(
        [*node, str(runner), str(extension), str(cases), str(cwd)],
        env=env,
        cwd=cwd,
        timeout=180,
        label="generated Pi extension",
    )
    try:
        payload = json.loads(completed.stdout.decode("utf-8"))
        results = payload["results"]
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
        raise ProbeError("generated Pi extension returned invalid result JSON") from exc
    if not isinstance(results, list) or not all(isinstance(result, dict) for result in results):
        raise ProbeError("generated Pi extension returned an invalid result list")
    return results


def _read_records(path: Path) -> dict[str, list[dict[str, Any]]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ProbeError(f"CLI wrapper did not write its capture log: {exc}") from exc
    grouped: dict[str, list[dict[str, Any]]] = {}
    for line in lines:
        try:
            record = json.loads(line)
            case_id = record["case_id"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ProbeError("CLI wrapper capture log contains invalid JSON") from exc
        if not isinstance(case_id, str) or not isinstance(record, dict):
            raise ProbeError("CLI wrapper capture log has an invalid record")
        grouped.setdefault(case_id, []).append(record)
    return grouped


def _payload_from_record(record: Mapping[str, Any]) -> dict[str, Any]:
    try:
        raw = base64.b64decode(str(record["stdin_b64"]), validate=True)
        payload = json.loads(raw.decode("utf-8"))
    except (KeyError, ValueError, UnicodeDecodeError) as exc:
        raise ProbeError("CLI wrapper captured invalid request payload") from exc
    if not isinstance(payload, dict):
        raise ProbeError("CLI wrapper captured a non-object request payload")
    return payload


def _response_from_record(record: Mapping[str, Any]) -> dict[str, Any] | None:
    try:
        stdout = base64.b64decode(str(record["stdout_b64"]), validate=True).decode("utf-8")
    except (KeyError, ValueError, UnicodeDecodeError) as exc:
        raise ProbeError("CLI wrapper captured invalid stdout") from exc
    for line in reversed(stdout.splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and "decision" in value:
            return value
    return None


def _assert_real_results(
    results: list[dict[str, Any]],
    records: dict[str, list[dict[str, Any]]],
    cases: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    by_id = {str(result.get("id")): result for result in results}
    expected_ids = {str(case["id"]) for case in cases}
    if set(by_id) != expected_ids:
        raise ProbeError("generated extension did not return every real case")
    evidence: dict[str, dict[str, Any]] = {}
    for case in cases:
        case_id = str(case["id"])
        matching = records.get(case_id, [])
        if not matching:
            raise ProbeError(f"real installed CLI was not invoked for {case_id}")
        record = matching[-1]
        payload = _payload_from_record(record)
        if payload.get("hook_event_name") != "PostToolUse" or payload.get("tool_call_id") != case_id:
            raise ProbeError(f"CLI payload identity mismatch for {case_id}")
        if payload.get("tool_response") != case["content"]:
            raise ProbeError(f"CLI payload lost full canonical content for {case_id}")
        if record.get("returncode") != 0:
            raise ProbeError(f"{case_id} CLI exited nonzero: {record.get('returncode')!r}")
        response = _response_from_record(record)
        result = by_id[case_id]
        digest, chars, excerpt = _text_digest(case["content"])
        preserved = result.get("preserved") is True
        if case_id != "large-nonsource":
            if not preserved or not isinstance(response, dict):
                raise ProbeError(f"{case_id} did not preserve a parsed full-proof result")
            if (
                response.get("decision") != "allow"
                or response.get("model_output_action") != "allow_original"
                or response.get("reviewed_output_sha256") != digest
            ):
                raise ProbeError(f"{case_id} preserved output without an exact full-output proof")
        elif preserved:
            if (
                not isinstance(response, dict)
                or response.get("decision") != "allow"
                or response.get("model_output_action") != "allow_original"
                or response.get("reviewed_output_sha256") != digest
            ):
                raise ProbeError("large-nonsource preserved output without an exact full-output proof")
        else:
            returned = result.get("result")
            content = returned.get("content") if isinstance(returned, dict) else None
            first = content[0] if isinstance(content, list) and content else None
            text = first.get("text") if isinstance(first, dict) else None
            if (
                not isinstance(response, dict)
                or response.get("decision") != "allow"
                or response.get("model_output_action") != "replace_with_reviewed_excerpt"
                or not isinstance(text, str)
                or text != excerpt
            ):
                raise ProbeError("large-nonsource did not return the exact bounded reviewed excerpt")
        evidence[case_id] = {
            "cli_returncode": record.get("returncode"),
            "decision": response.get("decision") if response else None,
            "model_output_action": response.get("model_output_action") if response else None,
            "sha256": digest,
            "chars": chars,
            "excerpt_chars": len(excerpt),
            "preserved": preserved,
        }
    return evidence


def _assert_negative_results(
    results: list[dict[str, Any]],
    records: dict[str, list[dict[str, Any]]],
) -> dict[str, dict[str, Any]]:
    by_id = {str(result.get("id")): result for result in results}
    expected_ids = {str(case["id"]) for case in _negative_cases()}
    if set(by_id) != expected_ids:
        raise ProbeError("generated extension did not return every malformed-result case")
    evidence: dict[str, dict[str, Any]] = {}
    for case_id, result in by_id.items():
        matching = records.get(case_id, [])
        if not matching:
            raise ProbeError(f"negative CLI wrapper was not invoked for {case_id}")
        record = matching[-1]
        if case_id == "negative-nonzero-allow" and record.get("returncode") == 0:
            raise ProbeError("negative nonzero CLI case unexpectedly exited zero")
        preserved = result.get("preserved") is True
        response: dict[str, Any] | None = None
        if case_id == "negative-observe":
            response = _response_from_record(record)
            if record.get("returncode") != 0:
                raise ProbeError("explicit observe response exited nonzero")
            if not preserved or not isinstance(response, dict):
                raise ProbeError("explicit observe response was not preserved")
            if response.get("decision") != "allow" or response.get("observe_mode") is not True:
                raise ProbeError("explicit observe response lacked canonical allow metadata")
        elif preserved:
            raise ProbeError(f"malformed result silently preserved output: {case_id}")
        else:
            returned = result.get("result")
            if not isinstance(returned, dict) or returned.get("isError") is not True:
                raise ProbeError(f"malformed result was not visibly blocked: {case_id}")
        evidence[case_id] = {
            "cli_invocations": len(matching),
            "preserved": preserved,
            "observe_mode": (
                response.get("observe_mode") if case_id == "negative-observe" and isinstance(response, dict) else None
            ),
            "is_error": bool(isinstance(result.get("result"), dict) and result["result"].get("isError")),
        }
    return evidence


def _probe_native_identity() -> tuple[Any, Any, Any]:
    from codex_plugin_scanner.guard.config import hook_fast_path_enabled
    from codex_plugin_scanner.guard.native_runtime import native_mode, native_runtime_status

    if native_mode() != "auto":
        raise ProbeError(f"unexpected native mode: {native_mode()}")
    if not hook_fast_path_enabled():
        raise ProbeError("unset fast-path configuration must be enabled")
    status = native_runtime_status()
    if not status.available or not status.compatible or status.reason != "native_ready":
        raise ProbeError(f"installed native runtime is not ready: {status}")
    if status.identity is None or status.capabilities is None:
        raise ProbeError(f"installed native runtime identity is incomplete: {status}")
    return status, status.identity, status.capabilities


def _native_state_files(guard_home: Path) -> tuple[Path, ...]:
    try:
        return tuple((guard_home / "native-runtime").glob("resident-v3-*/generation-*.json"))
    except (OSError, RuntimeError):
        return ()


def _native_cleanup_environment() -> dict[str, str]:
    allowed = {
        "COMSPEC",
        "HOME",
        "LANG",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
    return {key: value for key, value in os.environ.items() if key in allowed or key.upper().startswith("LC_")}


def _cleanup_native(identity: Any, guard_home: Path) -> None:
    from codex_plugin_scanner.guard.native_resident_client import (
        close_native_residents,
        stop_native_resident,
    )

    cleanup_error: OSError | RuntimeError | None = None
    try:
        contained = close_native_residents(guard_home)
    except (OSError, RuntimeError) as exc:
        contained = False
        cleanup_error = exc
    if _native_state_files(guard_home):
        try:
            if not stop_native_resident(
                executable=identity.path,
                state_dir=guard_home / "native-runtime",
                environment=_native_cleanup_environment(),
                timeout_seconds=2.0,
            ):
                cleanup_error = cleanup_error or RuntimeError("native resident stop did not complete")
        except (OSError, RuntimeError) as exc:
            cleanup_error = cleanup_error or exc
    if cleanup_error is None and not contained:
        try:
            contained = close_native_residents(guard_home)
        except (OSError, RuntimeError) as exc:
            cleanup_error = exc
    if cleanup_error is None and not contained:
        cleanup_error = RuntimeError("native resident containment did not complete")
    if cleanup_error is None and _native_state_files(guard_home):
        cleanup_error = RuntimeError("native resident state remained after cleanup")
    if cleanup_error is not None:
        raise ProbeError(f"authenticated native cleanup failed: {type(cleanup_error).__name__}") from cleanup_error


def _remove_probe_path(path: Path) -> bool:
    try:
        if not path.exists() and not path.is_symlink():
            return True
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    except OSError:
        return False
    return True


def _scrub_probe_root(root: Path, *, preserve_native_state: bool = False) -> int:
    """Remove probe captures while preserving only scoped native retry state."""
    if not root.exists():
        return 0
    if root.is_symlink():
        return 1
    try:
        children = tuple(root.iterdir())
    except OSError:
        return 1
    failures = 0
    for child in children:
        if preserve_native_state and child == root / "guard-home" and child.is_dir() and not child.is_symlink():
            native_state = child / "native-runtime"
            preserve_state = native_state.is_dir() and not native_state.is_symlink()
            if not preserve_state:
                if not _remove_probe_path(child):
                    failures += 1
                continue
            try:
                nested = tuple(child.iterdir())
            except OSError:
                failures += 1
                continue
            for nested_child in nested:
                if preserve_state and nested_child == native_state:
                    continue
                if not _remove_probe_path(nested_child):
                    failures += 1
            continue
        if not _remove_probe_path(child):
            failures += 1
    return failures


def _remaining_probe_paths(root: Path, *, preserve_native_state: bool = False) -> int:
    if not root.exists():
        return 0
    if root.is_symlink():
        return 1
    try:
        children = tuple(root.iterdir())
    except OSError:
        return 1
    remaining = 0
    for child in children:
        if preserve_native_state and child == root / "guard-home" and child.is_dir() and not child.is_symlink():
            native_state = child / "native-runtime"
            preserve_state = native_state.is_dir() and not native_state.is_symlink()
            if not preserve_state:
                remaining += 1
                continue
            try:
                nested = tuple(child.iterdir())
            except OSError:
                remaining += 1
                continue
            remaining += sum(not (preserve_state and nested_child == native_state) for nested_child in nested)
            continue
        remaining += 1
    return remaining


def _retain_cleanup_receipt(root: Path, failure: BaseException) -> None:
    """Retain only redacted retry state when authenticated cleanup cannot finish."""
    scrub_failures = _scrub_probe_root(root, preserve_native_state=True)
    remaining_paths = _remaining_probe_paths(root, preserve_native_state=True)
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        (root / "cleanup-failure.json").write_text(
            json.dumps(
                {
                    "schema": "hol-guard.installed-pi-cleanup-failure.v1",
                    "probe_root": str(root),
                    "error_type": type(failure).__name__,
                    "remaining_nonretry_paths": remaining_paths,
                    "retry_required": True,
                    "scrub_complete": scrub_failures == 0 and remaining_paths == 0,
                    "scrub_failures": scrub_failures,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ProbeError("redacted cleanup receipt could not be written") from exc
    if scrub_failures or remaining_paths:
        raise ProbeError("probe capture scrub could not be confirmed")


def _remove_probe_root(root: Path) -> None:
    try:
        shutil.rmtree(root)
    except OSError as exc:
        try:
            _retain_cleanup_receipt(root, exc)
        except ProbeError as scrub_failure:
            raise scrub_failure from exc
        raise ProbeError("probe scratch cleanup failed") from exc


def _run_probe(*, json_path: Path | None = None) -> dict[str, Any]:
    if os.name == "nt":
        raise ProbeError("installed Pi/native output probe is POSIX-only")
    _installed_package_path(_REPO_ROOT)
    status, identity, capabilities = _probe_native_identity()
    node = _node_command()
    python_path = Path(sys.executable).resolve()

    root = Path(tempfile.mkdtemp(prefix="hg-pi-native-", dir=_short_temp_parent()))
    native_started = False
    receipt: dict[str, Any] | None = None
    try:
        home = root / "home"
        guard_home = root / "guard-home"
        workspace = root / "workspace"
        for directory in (home, guard_home, workspace):
            directory.mkdir(mode=0o700)
        settings = root / "settings.json"
        settings.write_text("{}\n", encoding="utf-8")
        runner = root / "run-extension.mjs"
        _write_node_runner(runner)
        cases = _cases()
        cases_path = root / "cases.json"
        cases_path.write_text(json.dumps(cases, ensure_ascii=True), encoding="utf-8")
        real_log = root / "real-cli.jsonl"
        real_cli = home / ".local" / "bin" / "hol-guard"
        real_cli.parent.mkdir(mode=0o700, parents=True)
        _write_cli_wrapper(real_cli, python_path=python_path, log_path=real_log, negative=False)
        extension = root / "extension.ts"
        _generate_extension(
            extension,
            guard_home=guard_home,
            home=home,
            settings_path=settings,
        )
        version_module = importlib.import_module("codex_plugin_scanner.version")
        package_version = str(getattr(version_module, "__version__", "unknown"))
        native_started = True
        real_results = _run_node_cases(
            node=node,
            extension=extension,
            runner=runner,
            cases=cases_path,
            cwd=workspace,
            env=_isolated_env(home=home, python_path=python_path),
        )
        real_evidence = _assert_real_results(real_results, _read_records(real_log), cases)
        negative_home = root / "negative-home"
        negative_guard_home = root / "negative-guard-home"
        negative_workspace = root / "negative-workspace"
        for directory in (negative_home, negative_guard_home, negative_workspace):
            directory.mkdir(mode=0o700)
        negative_log = root / "negative-cli.jsonl"
        negative_cli = negative_home / ".local" / "bin" / "hol-guard"
        negative_cli.parent.mkdir(mode=0o700, parents=True)
        _write_cli_wrapper(negative_cli, python_path=python_path, log_path=negative_log, negative=True)
        negative_extension = root / "negative-extension.ts"
        _generate_extension(
            negative_extension,
            guard_home=negative_guard_home,
            home=negative_home,
            settings_path=root / "negative-settings.json",
        )
        negative_cases_path = root / "negative-cases.json"
        negative_cases = _negative_cases()
        negative_cases_path.write_text(json.dumps(negative_cases, ensure_ascii=True), encoding="utf-8")
        negative_results = _run_node_cases(
            node=node,
            extension=negative_extension,
            runner=runner,
            cases=negative_cases_path,
            cwd=negative_workspace,
            env=_isolated_env(home=negative_home, python_path=python_path),
        )
        negative_evidence = _assert_negative_results(negative_results, _read_records(negative_log))
        receipt = {
            "schema": "hol-guard.installed-pi-native-output.v1",
            "package_version": package_version,
            "source_sha": getattr(capabilities, "build_sha", None),
            "package_origin_kind": "installed-wheel",
            "source_checkout_import": False,
            "execution_path": "installed-cli",
            "native_prerequisite": "default-auto-status-checked",
            "workflow_order": "after-native-default-auto-probe",
            "runtime": {
                "mode": status.mode,
                "reason": status.reason,
                "target": getattr(capabilities, "target", None),
                "runtime_version": getattr(capabilities, "runtime_version", None),
                "build_sha": getattr(capabilities, "build_sha", None),
                "runtime_sha256": getattr(identity, "sha256", None),
            },
            "generated_extension": {
                "harness": "omp",
                "real_cases": real_evidence,
                "malformed_result_cases": negative_evidence,
            },
            "cleanup": "authenticated_native_resident_stop",
        }
    finally:
        cleanup_failure: ProbeError | None = None
        if native_started:
            try:
                _cleanup_native(identity, guard_home)
            except ProbeError as exc:
                cleanup_failure = exc
        if cleanup_failure is not None:
            try:
                _retain_cleanup_receipt(root, cleanup_failure)
            except ProbeError as scrub_failure:
                raise scrub_failure from cleanup_failure
            raise cleanup_failure
        _remove_probe_root(root)

    if receipt is None:
        raise ProbeError("installed Pi/native probe did not produce a receipt")
    if json_path is not None:
        json_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def main(*, json_path: Path | None = None) -> int:
    receipt = _run_probe(json_path=json_path)
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    try:
        raise SystemExit(main(json_path=args.json))
    except (ProbeError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
