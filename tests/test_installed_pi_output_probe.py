"""Unit coverage for the installed Pi/native output probe contract."""

from __future__ import annotations

import base64
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.native_runtime import probe_installed_pi_output as probe
from ci.native_runtime.probe_installed_pi_output import (
    ProbeError,
    _assert_negative_results,
    _assert_real_results,
    _cases,
    _is_source_checkout_package,
    _negative_cases,
    _retain_cleanup_receipt,
    _run_probe,
    _text_digest,
)


def _record(
    case: dict[str, object],
    response: dict[str, object] | None,
    *,
    returncode: int = 0,
) -> dict[str, object]:
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_call_id": case["id"],
        "tool_response": case["content"],
    }
    stdout = b"" if response is None else (json.dumps(response) + "\n").encode("utf-8")
    return {
        "case_id": case["id"],
        "returncode": returncode,
        "stdin_b64": base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii"),
        "stdout_b64": base64.b64encode(stdout).decode("ascii"),
        "stderr_b64": base64.b64encode(b"").decode("ascii"),
    }


def test_installed_origin_guard_rejects_checkout_package_only(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    checkout_package = repo_root / "src" / "codex_plugin_scanner" / "__init__.py"
    wheel_package = tmp_path / "venv" / "lib" / "site-packages" / "codex_plugin_scanner" / "__init__.py"

    assert _is_source_checkout_package(checkout_package, repo_root)
    assert not _is_source_checkout_package(wheel_package, repo_root)


def test_case_digest_preserves_crlf_unicode_and_ignores_metadata() -> None:
    case = _cases()[2]
    digest, chars, excerpt = _text_digest(case["content"])

    assert chars == len("first line\r\nsecond line: \U0001f600\n")
    assert excerpt == "first line\r\nsecond line: \U0001f600\n"
    assert len(digest) == 64


def test_real_validation_requires_status_zero_and_exact_full_proof() -> None:
    case = _cases()[0]
    digest, _, _ = _text_digest(case["content"])
    result = {"id": case["id"], "preserved": True, "result": None}
    valid_record = _record(
        case,
        {"decision": "allow", "model_output_action": "allow_original", "reviewed_output_sha256": digest},
    )

    evidence = _assert_real_results([result], {str(case["id"]): [valid_record]}, [case])
    assert evidence[str(case["id"])]["preserved"] is True

    nonzero = deepcopy(valid_record)
    nonzero["returncode"] = 2
    with pytest.raises(ProbeError, match="exited nonzero"):
        _assert_real_results([result], {str(case["id"]): [nonzero]}, [case])

    mismatched = deepcopy(valid_record)
    mismatched["stdout_b64"] = base64.b64encode(
        b'{"decision":"allow","model_output_action":"allow_original","reviewed_output_sha256":"' + b"0" * 64 + b'"}\n'
    ).decode("ascii")
    with pytest.raises(ProbeError, match="exact full-output proof"):
        _assert_real_results([result], {str(case["id"]): [mismatched]}, [case])

    payload_changed = deepcopy(valid_record)
    changed_payload = json.loads(base64.b64decode(payload_changed["stdin_b64"]).decode("utf-8"))
    changed_payload["tool_response"] = []
    payload_changed["stdin_b64"] = base64.b64encode(json.dumps(changed_payload).encode("utf-8")).decode("ascii")
    with pytest.raises(ProbeError, match="full canonical content"):
        _assert_real_results([result], {str(case["id"]): [payload_changed]}, [case])


def test_large_non_source_accepts_only_bounded_reviewed_excerpt() -> None:
    case = _cases()[3]
    _, _, excerpt = _text_digest(case["content"])
    result = {
        "id": case["id"],
        "preserved": False,
        "result": {"content": [{"type": "text", "text": excerpt}]},
    }
    record = _record(
        case,
        {"decision": "allow", "model_output_action": "replace_with_reviewed_excerpt"},
    )

    evidence = _assert_real_results([result], {str(case["id"]): [record]}, [case])
    assert evidence[str(case["id"])]["preserved"] is False

    arbitrary_excerpt = deepcopy(result)
    arbitrary_excerpt["result"]["content"][0]["text"] = "x" * len(excerpt)
    with pytest.raises(ProbeError, match="exact bounded reviewed excerpt"):
        _assert_real_results([arbitrary_excerpt], {str(case["id"]): [record]}, [case])


def test_cleanup_failure_scrubs_raw_probe_captures(tmp_path: Path) -> None:
    root = tmp_path / "probe-root"
    root.mkdir()
    native_state = root / "guard-home" / "native-runtime"
    native_state.mkdir(parents=True)
    (native_state / "generation-state.json").write_text("scoped state", encoding="utf-8")
    (root / "real-cli.jsonl").write_text('{"stdout_b64":"raw-capture"}\n', encoding="utf-8")
    (root / "stderr.txt").write_text("raw stderr", encoding="utf-8")

    _retain_cleanup_receipt(root, ProbeError("raw failure detail"))

    assert sorted(path.name for path in root.iterdir()) == ["cleanup-failure.json", "guard-home"]
    assert (native_state / "generation-state.json").read_text(encoding="utf-8") == "scoped state"
    marker = json.loads((root / "cleanup-failure.json").read_text(encoding="utf-8"))
    assert marker == {
        "error_type": "ProbeError",
        "probe_root": str(root),
        "remaining_nonretry_paths": 0,
        "retry_required": True,
        "scrub_complete": True,
        "scrub_failures": 0,
        "schema": "hol-guard.installed-pi-cleanup-failure.v1",
    }
    assert "raw" not in (root / "cleanup-failure.json").read_text(encoding="utf-8")


def test_cleanup_scrub_failure_is_redacted_and_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "probe-root"
    root.mkdir()
    raw_capture = root / "real-cli.jsonl"
    raw_capture.write_text('{"stdout_b64":"secret-capture"}\n', encoding="utf-8")
    original_remove = probe._remove_probe_path

    def refuse_raw_capture(path: Path) -> bool:
        if path == raw_capture:
            return False
        return original_remove(path)

    monkeypatch.setattr(probe, "_remove_probe_path", refuse_raw_capture)

    with pytest.raises(ProbeError, match="scrub could not be confirmed") as caught:
        _retain_cleanup_receipt(root, ProbeError("secret failure detail"))

    assert "secret" not in str(caught.value)
    marker_text = (root / "cleanup-failure.json").read_text(encoding="utf-8")
    marker = json.loads(marker_text)
    assert marker["scrub_complete"] is False
    assert marker["scrub_failures"] == 1
    assert marker["remaining_nonretry_paths"] == 1
    assert "secret-capture" not in marker_text
    assert raw_capture.exists()


def test_cleanup_failure_does_not_write_success_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "probe-root"
    root.mkdir()
    receipt_path = tmp_path / "installed-pi-output.json"
    status = SimpleNamespace(mode="auto", reason="native_ready")
    identity = SimpleNamespace(path=Path("/bin/false"), sha256="runtime-sha")
    capabilities = SimpleNamespace(build_sha="source-sha", target="test", runtime_version="test")

    monkeypatch.setattr("ci.native_runtime.probe_installed_pi_output.tempfile.mkdtemp", lambda **_: str(root))
    monkeypatch.setattr("ci.native_runtime.probe_installed_pi_output._installed_package_path", lambda _: root)
    monkeypatch.setattr(
        "ci.native_runtime.probe_installed_pi_output._probe_native_identity",
        lambda: (status, identity, capabilities),
    )
    monkeypatch.setattr("ci.native_runtime.probe_installed_pi_output._node_command", lambda: ["node"])
    monkeypatch.setattr(
        "ci.native_runtime.probe_installed_pi_output._write_node_runner", lambda path: path.write_text("")
    )
    monkeypatch.setattr(
        "ci.native_runtime.probe_installed_pi_output._generate_extension", lambda path, **kwargs: path.write_text("")
    )
    monkeypatch.setattr(
        "ci.native_runtime.probe_installed_pi_output._run_node_cases",
        lambda **kwargs: (_ for _ in ()).throw(ProbeError("real probe failed")),
    )
    monkeypatch.setattr(
        "ci.native_runtime.probe_installed_pi_output._cleanup_native",
        lambda identity, guard_home: (_ for _ in ()).throw(ProbeError("cleanup failed")),
    )

    with pytest.raises(ProbeError, match="cleanup failed"):
        _run_probe(json_path=receipt_path)

    assert not receipt_path.exists()
    assert (root / "cleanup-failure.json").exists()
    assert not (root / "real-cli.jsonl").exists()


def test_malformed_results_are_visible_blocks_but_observe_remains_preserved() -> None:
    cases = _negative_cases()
    results = []
    records = {}
    for case in cases:
        observe = case["id"] == "negative-observe"
        response = {"decision": "allow", "observe_mode": True} if observe else None
        results.append(
            {
                "id": case["id"],
                "preserved": observe,
                "result": None if observe else {"isError": True},
            }
        )
        records[str(case["id"])] = [
            _record(case, response, returncode=2 if case["id"] == "negative-nonzero-allow" else 0)
        ]

    evidence = _assert_negative_results(results, records)
    assert evidence["negative-observe"]["preserved"] is True
    assert evidence["negative-empty"]["is_error"] is True

    malformed_allow = next(result for result in results if result["id"] == "negative-malformed")
    malformed_allow["preserved"] = True
    with pytest.raises(ProbeError, match="silently preserved"):
        _assert_negative_results(results, records)

    observe_case = next(case for case in cases if case["id"] == "negative-observe")
    for malformed in ({"decision": "allow"}, {"decision": "allow", "observe_mode": "yes"}):
        malformed_records = deepcopy(records)
        malformed_results = deepcopy(results)
        next(result for result in malformed_results if result["id"] == "negative-malformed")["preserved"] = False
        malformed_records["negative-observe"] = [_record(observe_case, malformed)]
        with pytest.raises(ProbeError, match="canonical allow metadata"):
            _assert_negative_results(malformed_results, malformed_records)
