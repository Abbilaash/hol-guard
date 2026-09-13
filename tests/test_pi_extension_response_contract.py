"""Focused runtime contract tests for the generated Pi/OMP hook extension."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from codex_plugin_scanner.guard.daemon.hook_worker_responses import (
    harness_json_from_native_pre_tool,
    observe_lifecycle_fail_safe_response,
)


def _generated_source(tmp_path: Path) -> str:
    return managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="Oh My Pi",
    )


def _strip_generated_types(fragment: str) -> str:
    replacements = {
        "function compactHookEventName(value: unknown): string {": "function compactHookEventName(value) {",
        "function normalizeGuardResponse(value: unknown): GuardResponse | null {":
            "function normalizeGuardResponse(value) {",
        "  payload: Record<string, unknown>,": "  payload,",
        "  cwd?: string,": "  cwd,",
        "  options?: { enforceSizeCap?: boolean },": "  options,",
        "  reasonCode: string,": "  reasonCode,",
        "  reason: string,": "  reason,",
        "): GuardResponse {": ") {",
        "): Promise<GuardDaemonAttempt> {": ") {",
        "): Promise<GuardResponse> {": ") {",
        """async function daemonGuardResponse(
  serializedPayload: string,
  cwd?: string,
  timeoutMs: number = GUARD_DAEMON_TIMEOUT_MS,
  deadlineAt?: number,
): Promise<GuardDaemonAttempt> {""": """async function daemonGuardResponse(
  serializedPayload,
  cwd,
  timeoutMs = GUARD_DAEMON_TIMEOUT_MS,
  deadlineAt,
) {""",
        """async function runGuard(
  payload: Record<string, unknown>,
  cwd?: string,
  options?: { enforceSizeCap?: boolean },
): Promise<GuardResponse> {""": """async function runGuard(
  payload,
  cwd,
  options,
) {""",
        "let result: GuardCliResult | null = null;": "let result = null;",
        " as unknown": "",
        " as Record<string, unknown>": "",
        " as GuardResponse": "",
        " as { decision?: unknown }": "",
        """ as {
          error?: unknown;
        }""": "",
    }
    for old, new in replacements.items():
        fragment = fragment.replace(old, new)
    fragment = fragment.replace("  serializedPayload: string,", "  serializedPayload,")
    fragment = fragment.replace(
        "  timeoutMs: number = GUARD_DAEMON_TIMEOUT_MS,",
        "  timeoutMs = GUARD_DAEMON_TIMEOUT_MS,",
    )
    fragment = fragment.replace("  deadlineAt?: number,", "  deadlineAt,")
    return fragment


def _run_generated_fixture(source: str) -> dict[str, object]:
    helper_start = source.index("function normalizeGuardResponse(")
    helper_end = source.index("\n\nfunction loadGuardDaemonConnection(", helper_start)
    helper = _strip_generated_types(source[helper_start:helper_end])

    daemon_start = source.index("async function daemonGuardResponse(")
    daemon_end = source.index("\n\nasync function runGuard(", daemon_start)
    daemon = _strip_generated_types(source[daemon_start:daemon_end])

    run_start = source.index("async function runGuard(")
    run_end = source.index("\n\nfunction modelVisibleBlockedReason(", run_start)
    run_guard = _strip_generated_types(source[run_start:run_end])

    javascript = f"""\
const GUARD_DAEMON_TIMEOUT_MS = 3100;
const GUARD_HOME = "/tmp/omp-hook-contract/guard-home";
const GUARD_HOME_DIR_IS_DEFAULT = true;
const GUARD_HOME_DIR = "";
const GUARD_TEXT_LIMIT_CHARS = 12000;
const GUARD_TIMEOUT_MS = 4250;
const GUARD_DEADLINE_RESERVE_MS = 250;
const GUARD_DAEMON_RECOVERY_TIMEOUT_MS = 250;
const GUARD_DAEMON_RETRY_TIMEOUT_MS = 150;
const GUARD_CLI_TIMEOUT_MS = 300;
const GUARD_MAX_SERIALIZED_PAYLOAD_CHARS = 24000;
const GUARD_ARGS = [];
const GUARD_CLI_WRAPPER_COMMAND = "hol-guard";
const GUARD_CLI_WRAPPER_ARGS = [];
const GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS = false;
let guardCliContainmentFailed = false;
let guardCliEvaluationInFlight = false;
let daemonMode = "transport";
let fetchBodies = [];
let cliResult = {{ status: 0, stdout: "", stderr: "" }};
let daemonCalls = 0;
let recoveryCalls = 0;
let cliCalls = 0;

function loadGuardDaemonConnection() {{
  daemonCalls += 1;
  if (daemonMode === "transport") return null;
  if (daemonMode === "retry-transport" && daemonCalls === 1) return null;
  return {{ port: 1, authToken: "fixture-token" }};
}}

async function recoverGuardDaemon() {{
  recoveryCalls += 1;
  return daemonMode === "retry-transport" || daemonMode === "retry-shape";
}}

async function runGuardCliCommand() {{
  cliCalls += 1;
  return cliResult;
}}

globalThis.fetch = async () => ({{
  ok: true,
  status: 200,
  text: async () => fetchBodies.shift() ?? "",
}});

{helper}

{daemon}

{run_guard}

const result = {{}};
daemonMode = "http";
fetchBodies = ["{{\\"decision\\":\\"allow\\"}}"];
result.daemon_allow = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;
fetchBodies = ["{{\\"decision\\":\\"allow\\",\\"policy_action\\":\\"allow\\",\\"reason_code\\":\\"fixture_lifecycle\\"}}"];
result.daemon_lifecycle_allow = await runGuard({{ hook_event_name: "UserPromptSubmit" }});
fetchBodies = ["{{\\"decision\\":\\"deny\\",\\"reason\\":\\"fixture block\\"}}"];
result.daemon_deny = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;
fetchBodies = ["", "   "];
result.daemon_empty = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
result.daemon_whitespace = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
fetchBodies = ["not-json"];
result.daemon_malformed = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;
fetchBodies = ['{{"decision":"deny","reason":{{"nested":true}}}}'];
result.daemon_malformed_reason = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
fetchBodies = ['{{"decision":"deny","reason":null}}'];
result.daemon_null_reason = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;
fetchBodies = ['{{"decision":"deny"}}'];
result.daemon_omitted_reason = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;
fetchBodies = ['{{"policy_action":"allow"}}'];
result.daemon_shape = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
fetchBodies = ['[{{"decision":"allow"}}]'];
result.daemon_array = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
fetchBodies = ['{{"decision":"maybe"}}'];
result.daemon_unknown = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
fetchBodies = ['{{"decision":"block","reason":"fixture block"}}'];
result.daemon_block = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;

daemonMode = "retry-shape";
fetchBodies = ['{{"unknown":"first"}}', '{{"unknown":"second"}}'];
daemonCalls = 0;
recoveryCalls = 0;
cliCalls = 0;
cliResult = {{ status: 0, stdout: "", stderr: "" }};
result.retry_still_malformed = await runGuard({{ hook_event_name: "PreToolUse" }});
result.retry_still_malformed_daemon_calls = daemonCalls;
result.retry_still_malformed_recovery_calls = recoveryCalls;
result.retry_still_malformed_cli_calls = cliCalls;

daemonMode = "retry-shape";
fetchBodies = ['{{"decision":"deny","reason":{{"nested":true}}}}', '{{"decision":"deny","reason":{{"nested":true}}}}'];
daemonCalls = 0;
recoveryCalls = 0;
cliCalls = 0;
result.retry_malformed_reason = await runGuard({{ hook_event_name: "PostToolUse" }});
result.retry_malformed_reason_daemon_calls = daemonCalls;
result.retry_malformed_reason_recovery_calls = recoveryCalls;
result.retry_malformed_reason_cli_calls = cliCalls;

daemonMode = "retry-transport";
fetchBodies = ['{{"decision":"allow"}}'];
daemonCalls = 0;
recoveryCalls = 0;
cliCalls = 0;
result.retry_valid = await runGuard({{ hook_event_name: "PreToolUse" }});
result.retry_valid_daemon_calls = daemonCalls;
result.retry_valid_recovery_calls = recoveryCalls;
result.retry_valid_cli_calls = cliCalls;

daemonMode = "transport";
fetchBodies = [];
cliResult = {{ status: 0, stdout: '{{"policy_action":"allow"}}', stderr: "" }};
result.cli_missing_decision = await runGuard({{ hook_event_name: "PreToolUse" }});
cliResult = {{ status: 0, stdout: "", stderr: "" }};
result.cli_empty_prompt = await runGuard({{ hook_event_name: "UserPromptSubmit" }});
result.cli_empty_post = await runGuard({{ hook_event_name: "PostToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"deny","reason":{{"nested":true}}}}', stderr: "" }};
result.cli_malformed_reason = await runGuard({{ hook_event_name: "PostToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"deny","reason":null}}', stderr: "" }};
result.cli_null_reason = await runGuard({{ hook_event_name: "PostToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"deny"}}', stderr: "" }};
result.cli_omitted_reason = await runGuard({{ hook_event_name: "PostToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"allow","policy_action":"allow"}}', stderr: "" }};
result.cli_lifecycle_allow = await runGuard({{ hook_event_name: "UserPromptSubmit" }});
cliResult = {{ status: 0, stdout: '{{"decision":"allow"}}', stderr: "" }};
result.cli_allow = await runGuard({{ hook_event_name: "PreToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"deny","reason":"fixture block"}}', stderr: "" }};
result.cli_deny = await runGuard({{ hook_event_name: "PreToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"block","reason":"fixture block"}}', stderr: "" }};
result.cli_block_prompt = await runGuard({{ hook_event_name: "UserPromptSubmit" }});
result.cli_block_post = await runGuard({{ hook_event_name: "PostToolUse" }});

console.log(JSON.stringify(result));
"""
    with tempfile.NamedTemporaryFile("w", suffix=".mjs", prefix="omp-hook-contract-", delete=False) as fixture:
        fixture.write(javascript)
        fixture_path = fixture.name
    try:
        completed = subprocess.run(
            ["node", fixture_path],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        Path(fixture_path).unlink(missing_ok=True)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_canonical_omp_allow_deny_and_lifecycle_shapes() -> None:
    allow = harness_json_from_native_pre_tool(
        "omp",
        {"decision": "allow", "minimum_action": "allow", "reason_code": "fixture_allow"},
    )
    deny = harness_json_from_native_pre_tool(
        "omp",
        {
            "decision": "deny",
            "minimum_action": "block",
            "reason": "fixture block",
            "reason_code": "fixture_block",
        },
    )
    lifecycle = observe_lifecycle_fail_safe_response(
        "omp",
        event_name="UserPromptSubmit",
        reason_code="fixture_lifecycle",
    )

    assert allow["decision"] == "allow"
    assert deny["decision"] == "deny"
    assert lifecycle == {
        "decision": "allow",
        "policy_action": "allow",
        "reason_code": "fixture_lifecycle",
    }


def test_generated_omp_rejects_ambiguous_success_and_preserves_retry_semantics(tmp_path: Path) -> None:
    result = _run_generated_fixture(_generated_source(tmp_path))

    assert result["daemon_allow"] == {"decision": "allow"}
    assert result["daemon_lifecycle_allow"] == {
        "decision": "allow",
        "policy_action": "allow",
        "reason_code": "fixture_lifecycle",
    }
    assert result["daemon_deny"] == {"decision": "deny", "reason": "fixture block"}
    assert result["daemon_empty"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_whitespace"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_malformed"] == {
        "decision": "deny",
        "reason": "HOL Guard received an invalid response from the authenticated local daemon.",
        "reason_code": "daemon_invalid_response",
    }
    assert result["daemon_malformed_reason"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_null_reason"] == {"decision": "deny", "reason": None}
    assert result["daemon_omitted_reason"] == {"decision": "deny"}
    assert result["daemon_shape"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_array"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_unknown"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_block"] == {"decision": "deny", "reason": "fixture block"}

    assert result["retry_still_malformed"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["retry_still_malformed_daemon_calls"] == 2
    assert result["retry_still_malformed_recovery_calls"] == 1
    assert result["retry_still_malformed_cli_calls"] == 1

    assert result["retry_malformed_reason"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["retry_malformed_reason_daemon_calls"] == 2
    assert result["retry_malformed_reason_recovery_calls"] == 1
    assert result["retry_malformed_reason_cli_calls"] == 1

    assert result["retry_valid"] == {"decision": "allow"}
    assert result["retry_valid_daemon_calls"] == 2
    assert result["retry_valid_recovery_calls"] == 1
    assert result["retry_valid_cli_calls"] == 0

    assert result["cli_missing_decision"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["cli_empty_prompt"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["cli_empty_post"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["cli_malformed_reason"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["cli_null_reason"] == {"decision": "deny", "reason": None}
    assert result["cli_omitted_reason"] == {"decision": "deny"}
    assert result["cli_lifecycle_allow"] == {"decision": "allow", "policy_action": "allow"}
    assert result["cli_allow"] == {"decision": "allow"}
    assert result["cli_deny"] == {"decision": "deny", "reason": "fixture block"}
    assert result["cli_block_prompt"] == {"decision": "deny", "reason": "fixture block"}
    assert result["cli_block_post"] == {"decision": "deny", "reason": "fixture block"}
