"""Run a synthetic two-user registration lab against a pinned Headscale build.

All state and receipts stay below --build-dir. No auth key enters a receipt.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import time
from urllib.request import urlopen

from headscale_enrollment_gate import EnrollmentGate, GateError, HeadscaleCLI


PIN = "eeaac680bef26585c8cc1569f949e26d0d6aba80"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*args: str, input_text: str | None = None, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, input=input_text, text=True, capture_output=True,
        timeout=timeout, check=False,
    )


def port_number() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def config_from_pinned_example(example: Path, run_dir: Path, sock_path: Path, port: int) -> Path:
    config = example.read_text()
    state = run_dir / "service-state"
    state.mkdir(mode=0o700)
    changes = {
        "server_url: http://127.0.0.1:8080": f"server_url: http://127.0.0.1:{port}",
        "listen_addr: 127.0.0.1:8080": f"listen_addr: 127.0.0.1:{port}",
        "metrics_listen_addr: 127.0.0.1:9090": 'metrics_listen_addr: ""',
        "private_key_path: /var/lib/headscale/noise_private.key":
            f"private_key_path: {state}/noise_private.key",
        "    - https://controlplane.tailscale.com/derpmap/default": "    []",
        "auto_update_enabled: true": "auto_update_enabled: false",
        "disable_check_updates: false": "disable_check_updates: true",
        "path: /var/lib/headscale/db.sqlite": f"path: {state}/db.sqlite",
        "unix_socket: /var/run/headscale/headscale.sock": f"unix_socket: {sock_path}",
        "magic_dns: true": "magic_dns: false",
        "base_domain: example.com": "base_domain: lab.invalid",
        '  path: ""': f"  path: {run_dir}/policy.hujson",
        "  paths: []": f"  paths:\n    - {run_dir}/derp-local.yaml",
    }
    for old, new in changes.items():
        if config.count(old) != 1:
            raise RuntimeError(f"pinned config field changed: {old}")
        config = config.replace(old, new)
    path = run_dir / "config.yaml"
    path.write_text(config)
    (run_dir / "policy.hujson").write_text(json.dumps({
        "tagOwners": {"tag:lab-a": [], "tag:lab-b": []},
        "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
    }))
    (run_dir / "derp-local.yaml").write_text(
        "regions:\n  901:\n    regionid: 901\n    regioncode: lab\n"
        "    regionname: Local Registration Lab\n    nodes:\n"
        "      - name: lab-a\n        regionid: 901\n"
        "        hostname: 127.0.0.1\n        ipv4: 127.0.0.1\n"
        "        stunport: 0\n        stunonly: false\n        derpport: 18099\n"
    )
    return path


def ready(url: str, process: subprocess.Popen) -> None:
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Headscale stopped before health check")
        try:
            with urlopen(url + "/health", timeout=1) as response:
                if json.load(response)["status"] == "pass":
                    return
        except (OSError, ValueError, KeyError):
            time.sleep(0.2)
    raise RuntimeError("Headscale health check timed out")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--headscale", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    args = parser.parse_args()
    if run("git", "-C", str(args.upstream), "rev-parse", "HEAD").stdout.strip() != PIN:
        raise RuntimeError("upstream reference is not the pinned commit")
    project = Path(__file__).resolve().parents[1]
    source_files = (
        "pyproject.toml", "MANIFEST.in",
        "src/headscale_enrollment_gate/__init__.py",
        "src/headscale_enrollment_gate/gate.py",
        "src/headscale_enrollment_gate/cli.py", "tests/test_gate.py",
        "lab/tsnetprobe.go", "lab/validate_live.py",
    )

    args.build_dir.mkdir(parents=True, exist_ok=True)
    run_dir = args.build_dir / ("run-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    run_dir.mkdir(mode=0o700)
    short_socket = args.build_dir.parents[1] / ("hseg-" + secrets.token_hex(4) + ".sock")
    port = port_number()
    url = f"http://127.0.0.1:{port}"
    config = config_from_pinned_example(
        args.upstream / "config-example.yaml", run_dir, short_socket, port
    )
    check = run(str(args.headscale), "-c", str(config), "configtest")
    if check.returncode:
        raise RuntimeError("Headscale configuration test failed")
    log_path = run_dir / "headscale.log"
    log = log_path.open("ab")
    process = None

    def start():
        nonlocal process
        process = subprocess.Popen(
            [str(args.headscale), "-c", str(config), "serve"],
            stdout=log, stderr=subprocess.STDOUT,
        )
        ready(url, process)

    def stop():
        nonlocal process
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        process = None

    def hs(*parts: str):
        response = run(str(args.headscale), "-c", str(config), "-o", "json", *parts)
        if response.returncode:
            raise RuntimeError(f"Headscale {parts[0]} command failed")
        return json.loads(response.stdout)

    def nodes():
        return hs("nodes", "list")

    def keys():
        return hs("preauthkeys", "list")

    def probe(key: str, hostname: str, timeout: int = 12, tags: str = "") -> bool:
        state = run_dir / "clients" / hostname
        state.parent.mkdir(exist_ok=True)
        env = dict(os.environ, TS_NO_LOGS_NO_SUPPORT="1")
        command = [str(args.probe), "-state", str(state), "-host", hostname,
                   "-control", url, "-timeout", f"{timeout}s"]
        if tags:
            command += ["-tags", tags]
        response = subprocess.run(
            command, input=json.dumps({"key": key}), text=True,
            capture_output=True, timeout=timeout + 10, env=env, check=False,
        )
        return response.returncode == 0 and '"online"' in response.stdout

    def assert_node(hostname: str, expected_user: str | None, expected_tags: list[str]):
        matches = [node for node in nodes() if node.get("name") == hostname]
        if len(matches) != 1:
            raise AssertionError(f"node {hostname} was not registered exactly once")
        node = matches[0]
        actual_user = (node.get("user") or {}).get("id")
        if expected_user is not None and actual_user != expected_user:
            raise AssertionError("node user differed from grant")
        if sorted(node.get("tags") or []) != sorted(expected_tags):
            raise AssertionError("node tags differed from grant")
        return {"id": node["id"], "name": hostname,
                "user_id": actual_user, "tags": node.get("tags") or []}

    result = {"status": "OPEN", "upstream_commit": PIN,
              "headscale_binary_sha256": sha(args.headscale),
              "probe_binary_sha256": sha(args.probe),
              "headscale_go_version": run("go", "version", "-m", str(args.headscale)).stdout.splitlines()[0],
              "probe_go_version": run("go", "version", "-m", str(args.probe)).stdout.splitlines()[0],
              "python_version": sys.version.split()[0],
              "source_sha256": {name: sha(project / name) for name in source_files},
              "upstream_license_sha256": sha(args.upstream / "LICENSE"),
              "config_sha256": sha(config), "events": []}
    try:
        start()
        alice = hs("users", "create", "alice")["id"]
        bob = hs("users", "create", "bob")["id"]
        if alice == bob:
            raise AssertionError("users collided")
        policy = run_dir / "gate-policy.json"
        policy.write_text(json.dumps({"version": 1, "audiences": {
            "alice-ops": {"personal_users": [alice],
                          "tagged": {alice: ["tag:lab-a"]}},
            "bob-ops": {"personal_users": [bob],
                        "tagged": {bob: ["tag:lab-b"]}},
        }}, sort_keys=True))
        db_path = run_dir / "gate.sqlite"
        gate = EnrollmentGate(db_path, policy, HeadscaleCLI(args.headscale, config))

        alice_grant, token, _ = gate.plan("alice-ops", "personal", alice, [], 300)
        alice_key = gate.redeem(token, "alice-ops", "personal", alice, [])
        if not probe(alice_key.secret, "lab-alice"):
            raise AssertionError("Alice client did not register")
        result["events"].append({"case": "personal_alice", "pass": True,
                                 "node": assert_node("lab-alice", alice, []),
                                 "key_id": alice_key.key_id})
        before = len(nodes())
        if probe(alice_key.secret, "lab-replay", timeout=8) or len(nodes()) != before:
            raise AssertionError("used key registered another node")
        result["events"].append({"case": "key_replay", "pass": True,
                                 "node_count_unchanged": True})
        gate = EnrollmentGate(db_path, policy, HeadscaleCLI(args.headscale, config))
        try:
            gate.redeem(token, "alice-ops", "personal", alice, [])
        except GateError:
            result["events"].append({"case": "grant_replay_after_gate_restart", "pass": True})
        else:
            raise AssertionError("grant replay succeeded")
        if gate.status(alice_grant)["status"] != "issued":
            raise AssertionError("used grant status changed")

        _, bob_token, _ = gate.plan("bob-ops", "personal", bob, [], 300)
        bob_key = gate.redeem(bob_token, "bob-ops", "personal", bob, [])
        if not probe(bob_key.secret, "lab-bob"):
            raise AssertionError("Bob client did not register")
        result["events"].append({"case": "personal_bob", "pass": True,
                                 "node": assert_node("lab-bob", bob, []),
                                 "key_id": bob_key.key_id})

        _, cross_token, _ = gate.plan("alice-ops", "personal", alice, [], 300)
        try:
            gate.redeem(cross_token, "alice-ops", "personal", bob, [])
        except GateError:
            result["events"].append({"case": "cross_user_scope", "pass": True})
        else:
            raise AssertionError("cross-user change passed")

        _, tagged_token, _ = gate.plan(
            "alice-ops", "tagged", alice, ["tag:lab-a"], 300
        )
        try:
            gate.redeem(tagged_token, "alice-ops", "tagged", alice, ["tag:lab-b"])
        except GateError:
            result["events"].append({"case": "tag_mutation", "pass": True})
        else:
            raise AssertionError("tag change passed")
        tagged_key = gate.redeem(
            tagged_token, "alice-ops", "tagged", alice, ["tag:lab-a"]
        )
        if not probe(tagged_key.secret, "lab-tagged"):
            raise AssertionError("tagged client did not register")
        result["events"].append({"case": "tagged_registration", "pass": True,
                                 "node": assert_node("lab-tagged", None, ["tag:lab-a"]),
                                 "issuer_user_id": alice,
                                 "key_id": tagged_key.key_id})

        _, changed_tag_token, _ = gate.plan(
            "alice-ops", "tagged", alice, ["tag:lab-a"], 300
        )
        changed_tag_key = gate.redeem(
            changed_tag_token, "alice-ops", "tagged", alice, ["tag:lab-a"]
        )
        before = len(nodes())
        if (probe(changed_tag_key.secret, "lab-tag-mutated", timeout=8,
                  tags="tag:lab-b") or len(nodes()) != before):
            raise AssertionError("client advertised a tag outside the key scope")
        changed_tag_record = next(
            key for key in keys() if key["id"] == changed_tag_key.key_id
        )
        if changed_tag_record["used"]:
            raise AssertionError("rejected tag change consumed a key")
        hs("preauthkeys", "expire", "--id", changed_tag_key.key_id)
        result["events"].append({"case": "client_tag_mutation", "pass": True,
                                 "key_id": changed_tag_key.key_id,
                                 "node_count_unchanged": True,
                                 "key_unconsumed": True})

        expired_grant, expired_token, _ = gate.plan(
            "bob-ops", "personal", bob, [], 5
        )
        key_count = len(keys())
        time.sleep(5.2)
        try:
            gate.redeem(expired_token, "bob-ops", "personal", bob, [])
        except GateError:
            pass
        else:
            raise AssertionError("expired grant was redeemed")
        if len(keys()) != key_count:
            raise AssertionError("expired grant minted a key")
        result["events"].append({"case": "expired_grant", "pass": True,
                                 "key_count_unchanged": True,
                                 "grant_id": expired_grant})

        # Headscale's own key expiry is observed independently of the gate.
        headscale_expired = hs("preauthkeys", "create", "--user", bob,
                               "--expiration", "1s")
        time.sleep(2)
        before = len(nodes())
        if probe(headscale_expired["key"], "lab-expired", timeout=8) or len(nodes()) != before:
            raise AssertionError("Headscale accepted expired key")
        result["events"].append({"case": "headscale_key_expiry", "pass": True,
                                 "key_id": headscale_expired["id"],
                                 "node_count_unchanged": True})

        stop()
        start()
        gate = EnrollmentGate(db_path, policy, HeadscaleCLI(args.headscale, config))
        for replay_token, replay_audience, replay_user in (
            (token, "alice-ops", alice),
            (expired_token, "bob-ops", bob),
        ):
            try:
                gate.redeem(replay_token, replay_audience, "personal", replay_user, [])
            except GateError:
                pass
            else:
                raise AssertionError("grant became usable after restart")
        before = len(nodes())
        if probe(alice_key.secret, "lab-post-restart", timeout=8) or len(nodes()) != before:
            raise AssertionError("Headscale key became reusable after restart")
        result["events"].append({"case": "service_and_gate_restart", "pass": True,
                                 "node_count_unchanged": True})
        result["final_nodes"] = [
            {"id": node["id"], "name": node["name"],
             "user_id": (node.get("user") or {}).get("id"),
             "tags": node.get("tags") or []} for node in nodes()
        ]
        result["final_keys"] = [
            {"id": key["id"], "used": key["used"],
             "user_id": (key.get("user") or {}).get("id"),
             "tags": key.get("aclTags") or []} for key in keys()
        ]
        result["status"] = "PASS"
    finally:
        stop()
        log.close()
        if short_socket.exists():
            short_socket.unlink()
        result["completed_utc"] = datetime.now(timezone.utc).isoformat()
        (run_dir / "receipt.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        )
        # Synthetic node stores and the control-plane private key are not
        # retained after the receipt has captured the service observations.
        shutil.rmtree(run_dir / "clients", ignore_errors=True)
        shutil.rmtree(run_dir / "service-state", ignore_errors=True)
    print(json.dumps({"status": result["status"], "receipt": str(run_dir / "receipt.json"),
                      "cases": len(result["events"])}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
