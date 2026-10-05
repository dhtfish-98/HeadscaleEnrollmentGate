import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest

from headscale_enrollment_gate.gate import EnrollmentGate, GateError, MintedKey


class FakeIssuer:
    def __init__(self, clock):
        self.clock = clock
        self.calls = []
        self.expired = []
        self.fail = False
        self.delay = 0
        self.wrong_tags = False

    def mint(self, user_id, tags, ttl_seconds):
        self.calls.append((user_id, tags, ttl_seconds))
        if self.delay:
            time.sleep(self.delay)
        if self.fail:
            raise RuntimeError("unavailable")
        return MintedKey(
            secret="hskey-auth-SYNTHETIC", key_id=str(len(self.calls)),
            user_id=user_id, tags=("tag:wrong",) if self.wrong_tags else tags,
            expires_at=self.clock() + ttl_seconds, reusable=False, used=False,
        )

    def expire(self, key_id):
        self.expired.append(key_id)


class GateTests(unittest.TestCase):
    def setUp(self):
        root = os.environ.get("HSEG_BUILD")
        if not root:
            self.fail("HSEG_BUILD must point to a Build directory")
        self.temp = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = self.root / "policy.json"
        self.policy.write_text(json.dumps({
            "version": 1,
            "audiences": {
                "alice-ops": {"personal_users": ["1"],
                              "tagged": {"1": ["tag:lab-a"]}},
                "bob-ops": {"personal_users": ["2"],
                            "tagged": {"2": ["tag:lab-b"]}},
            },
        }))
        self.now = 1_000_000.0
        self.clock = lambda: self.now
        self.issuer = FakeIssuer(self.clock)
        self.db = self.root / "state" / "grants.sqlite"
        self.gate = EnrollmentGate(self.db, self.policy, self.issuer, self.clock)

    def test_personal_key_one_time_after_reopen(self):
        grant_id, token, _ = self.gate.plan("alice-ops", "personal", "1", [], 300)
        key = self.gate.redeem(token, "alice-ops", "personal", "1", [])
        self.assertEqual((key.user_id, key.tags, key.reusable), ("1", (), False))
        self.assertEqual(self.gate.status(grant_id)["status"], "issued")
        fresh = EnrollmentGate(self.db, self.policy, self.issuer, self.clock)
        with self.assertRaises(GateError):
            fresh.redeem(token, "alice-ops", "personal", "1", [])
        self.assertEqual(len(self.issuer.calls), 1)
        self.assertEqual(self.db.stat().st_mode & 0o077, 0)
        self.assertNotIn(key.secret, self.db.read_bytes().decode(errors="ignore"))

    def test_cross_user_and_tag_mutation_do_not_consume_grant(self):
        _, token, _ = self.gate.plan("alice-ops", "tagged", "1", ["tag:lab-a"], 300)
        for audience, user, tags in (
            ("bob-ops", "1", ["tag:lab-a"]),
            ("alice-ops", "2", ["tag:lab-a"]),
            ("alice-ops", "1", ["tag:lab-b"]),
        ):
            with self.assertRaises(GateError):
                self.gate.redeem(token, audience, "tagged", user, tags)
        self.assertEqual(self.issuer.calls, [])
        self.gate.redeem(token, "alice-ops", "tagged", "1", ["tag:lab-a"])
        self.assertEqual(self.issuer.calls[0][1], ("tag:lab-a",))

    def test_expired_grant_remains_closed_after_reopen(self):
        _, token, _ = self.gate.plan("alice-ops", "personal", "1", [], 5)
        self.now += 5
        fresh = EnrollmentGate(self.db, self.policy, self.issuer, self.clock)
        with self.assertRaises(GateError):
            fresh.redeem(token, "alice-ops", "personal", "1", [])
        self.assertEqual(self.issuer.calls, [])

    def test_clock_rollback_fails_closed_after_reopen(self):
        _, token, _ = self.gate.plan("alice-ops", "personal", "1", [], 300)
        self.now -= 1
        fresh = EnrollmentGate(self.db, self.policy, self.issuer, self.clock)
        with self.assertRaisesRegex(GateError, "clock moved backwards"):
            fresh.redeem(token, "alice-ops", "personal", "1", [])
        self.assertEqual(self.issuer.calls, [])

    def test_policy_revoke_before_redeem(self):
        _, token, _ = self.gate.plan("alice-ops", "personal", "1", [], 300)
        self.policy.write_text('{"version":1,"audiences":{}}')
        with self.assertRaises(GateError):
            self.gate.redeem(token, "alice-ops", "personal", "1", [])
        self.assertEqual(self.issuer.calls, [])

    def test_failed_issuance_is_not_retried(self):
        grant_id, token, _ = self.gate.plan("alice-ops", "personal", "1", [], 300)
        self.issuer.fail = True
        with self.assertRaises(GateError):
            self.gate.redeem(token, "alice-ops", "personal", "1", [])
        self.assertEqual(self.gate.status(grant_id)["status"], "failed")
        self.issuer.fail = False
        with self.assertRaises(GateError):
            self.gate.redeem(token, "alice-ops", "personal", "1", [])
        self.assertEqual(len(self.issuer.calls), 1)

    def test_mismatched_headscale_metadata_revokes_key(self):
        grant_id, token, _ = self.gate.plan("alice-ops", "tagged", "1", ["tag:lab-a"], 300)
        self.issuer.wrong_tags = True
        with self.assertRaises(GateError):
            self.gate.redeem(token, "alice-ops", "tagged", "1", ["tag:lab-a"])
        self.assertEqual(self.issuer.expired, ["1"])
        self.assertEqual(self.gate.status(grant_id)["status"], "failed")

    def test_concurrent_redeem_has_one_winner(self):
        _, token, _ = self.gate.plan("alice-ops", "personal", "1", [], 300)
        self.issuer.delay = 0.05
        results = []
        barrier = threading.Barrier(3)

        def redeem():
            barrier.wait()
            try:
                self.gate.redeem(token, "alice-ops", "personal", "1", [])
                results.append("ok")
            except GateError:
                results.append("closed")

        workers = [threading.Thread(target=redeem) for _ in range(2)]
        for worker in workers:
            worker.start()
        barrier.wait()
        for worker in workers:
            worker.join()
        self.assertCountEqual(results, ["ok", "closed"])
        self.assertEqual(len(self.issuer.calls), 1)

    def test_invalid_tags_and_scope_are_closed(self):
        for tags in (["tag:lab-a", "tag:lab-a"], ["bad"], ["tag:lab-b"]):
            with self.assertRaises(GateError):
                self.gate.plan("alice-ops", "tagged", "1", tags, 300)
        with self.assertRaises(GateError):
            self.gate.plan("alice-ops", "personal", "2", [], 300)


if __name__ == "__main__":
    unittest.main()
