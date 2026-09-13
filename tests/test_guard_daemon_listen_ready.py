from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_url
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.runtime_artifact_reconciliation import RuntimeArtifactReconciliation
from codex_plugin_scanner.guard.store import GuardStore


def test_daemon_serve_publishes_listen_state_before_artifact_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    configured_home = tmp_path / "configured-home"
    reconcile_started = threading.Event()
    release_reconcile = threading.Event()

    def reconcile(
        _store: GuardStore,
        *,
        home_dir: Path | None = None,
    ) -> RuntimeArtifactReconciliation:
        assert home_dir == configured_home
        reconcile_started.set()
        assert release_reconcile.wait(timeout=8)
        return RuntimeArtifactReconciliation(
            refreshed_launchers=("codex",),
            repaired_harnesses=("codex",),
            repaired_package_managers=("npm",),
            failed_harnesses=(),
            errors=(),
        )

    monkeypatch.setattr(daemon_server_module, "reconcile_runtime_artifacts", reconcile)
    daemon = GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
        home_dir=configured_home,
        idle_timeout_seconds=0,
    )
    monkeypatch.setattr(daemon._server.hook_process_runner, "require_initial_capacity", lambda: None)

    worker = threading.Thread(target=daemon.serve, name="guard-daemon-serve-test", daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + 8
        url = None
        while time.monotonic() < deadline:
            url = load_guard_daemon_url(store.guard_home)
            if url:
                break
            time.sleep(0.05)
        assert url is not None
        assert reconcile_started.wait(timeout=8)
        assert release_reconcile.is_set() is False
        records = [
            json.loads(line)
            for line in (store.guard_home / "logs" / "daemon.log").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        events = [record["event"] for record in records]
        assert "daemon_listen_ready" in events
        assert "runtime_artifact_reconciliation_completed" not in events
    finally:
        release_reconcile.set()
        daemon.stop()
        worker.join(timeout=8)
        assert worker.is_alive() is False


def test_serve_stop_during_reconcile_does_not_leave_background_workers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    reconcile_started = threading.Event()
    release_reconcile = threading.Event()

    def reconcile(
        _store: GuardStore,
        *,
        home_dir: Path | None = None,
    ) -> RuntimeArtifactReconciliation:
        del home_dir
        reconcile_started.set()
        assert release_reconcile.wait(timeout=8)
        return RuntimeArtifactReconciliation(
            refreshed_launchers=(),
            repaired_harnesses=(),
            repaired_package_managers=(),
            failed_harnesses=(),
            errors=(),
        )

    monkeypatch.setattr(daemon_server_module, "reconcile_runtime_artifacts", reconcile)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=0)
    monkeypatch.setattr(daemon._server.hook_process_runner, "require_initial_capacity", lambda: None)

    worker = threading.Thread(target=daemon.serve, name="guard-daemon-stop-during-reconcile", daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if load_guard_daemon_url(store.guard_home):
                break
            time.sleep(0.05)
        assert reconcile_started.wait(timeout=8)
        daemon.stop()
        assert daemon._command_queue_worker is None
        assert daemon._server.hook_process_runner.stats()["workers"] == 0
    finally:
        release_reconcile.set()
        daemon.stop()
        worker.join(timeout=8)
        assert worker.is_alive() is False
        assert daemon._command_queue_worker is None
        assert daemon._owner_lock is None


def test_desktop_owned_core_executable_prefers_runtime_owner(monkeypatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.dashboard_launcher import _desktop_owned_core_executable

    owner = tmp_path / "hol-guard"
    owner.write_text("#!/bin/sh\n", encoding="utf-8")
    owner.chmod(0o755)
    monkeypatch.setenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", str(owner))
    monkeypatch.setattr(sys, "frozen", False, raising=False)

    assert _desktop_owned_core_executable() == owner.resolve()


@pytest.mark.skipif(sys.platform == "win32", reason="Windows files do not use POSIX execute bits")
def test_desktop_owned_core_executable_ignores_non_executable_owner(
    monkeypatch, tmp_path: Path
) -> None:
    from codex_plugin_scanner.guard.dashboard_launcher import _desktop_owned_core_executable

    owner = tmp_path / "hol-guard"
    owner.write_text("not executable\n", encoding="utf-8")
    owner.chmod(0o644)
    monkeypatch.setenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", str(owner))
    monkeypatch.setattr(sys, "frozen", False, raising=False)

    assert _desktop_owned_core_executable() is None


def test_command_queue_refresh_does_not_block_while_startup_holds_lifecycle_lock(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    assert daemon._finish_service_lock.acquire(blocking=False)
    try:
        result = daemon.refresh_command_queue_worker()
    finally:
        daemon._finish_service_lock.release()
    assert result["running"] is False
    assert result["sync_running"] is False
