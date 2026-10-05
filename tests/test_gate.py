import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest

from headscale_enrollment_gate.gate import (
    EnrollmentGate, GateError, HeadscaleCLI, MintedKey,
)


class FakeIssuer:
    def __init__(self, clock):
        self.clock = clock
        self.calls = []
        self.expired = []
        self.fail = False
        self.expire_fail = False
        self.delay = 0
        self.wrong_tags = False
        self.bad_secret = False

    def mint(self, user_id, tags, ttl_seconds):
        self.calls.append((user_id, tags, ttl_seconds))
        if self.delay:
            time.sleep(self.delay)
        if self.fail:
            raise RuntimeError("unavailable")
        return MintedKey(
            secret="BAD" if self.bad_secret else "hskey-auth-SYNTHETIC",
            key_id=str(len(self.calls)),
            user_id=user_id, tags=("tag:wrong",) if self.wrong_tags else tags,
            expires_at=self.clock() + ttl_seconds, reusable=False, used=False,
        )

    def expire(self, key_id):
        self.expired.append(key_id)
        if self.expire_fail:
            raise RuntimeError("synthetic revocation failure")


class BlockingIssuer(FakeIssuer):
    def __init__(self, clock):
        super().__init__(clock)
        self.minted = threading.Event()
        self.release_mint = threading.Event()
        self.expiring = threading.Event()
        self.release_expire = threading.Event()
        self.block_expire = False

    def mint(self, user_id, tags, ttl_seconds):
        key = super().mint(user_id, tags, ttl_seconds)
        self.minted.set()
        if not self.release_mint.wait(5):
            raise RuntimeError("mint synchronization timed out")
        return key

    def expire(self, key_id):
        if self.block_expire:
            self.expiring.set()
            if not self.release_expire.wait(5):
                raise RuntimeError("expire synchronization timed out")
        super().expire(key_id)


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

    def _assert_malformed_policy_blocks_plan_and_redeem(self, bad_policy, mode):
        valid = {"version": 1, "audiences": {
            "ops": {"personal_users": ["2"],
                    "tagged": {"2": ["tag:lab-a"]}},
        }}
        self.policy.write_text(json.dumps(valid))
        tags = ["tag:lab-a"] if mode == "tagged" else []
        grant_id, token, _ = self.gate.plan("ops", mode, "2", tags, 300)
        self.policy.write_text(
            bad_policy if isinstance(bad_policy, str) else json.dumps(bad_policy)
        )
        with self.assertRaises(GateError):
            self.gate.plan("ops", mode, "2", tags, 300)
        with self.assertRaises(GateError):
            self.gate.redeem(token, "ops", mode, "2", tags)
        self.assertEqual(self.gate.status(grant_id)["status"], "pending")
        self.assertEqual(self.issuer.calls, [])

    def test_schema_personal_string_does_not_authorize_member(self):
        self._assert_malformed_policy_blocks_plan_and_redeem({
            "version": 1, "audiences": {"ops": {
                "personal_users": "123", "tagged": {},
            }},
        }, "personal")

    def test_schema_personal_false_mapping_does_not_authorize_key(self):
        self._assert_malformed_policy_blocks_plan_and_redeem({
            "version": 1, "audiences": {"ops": {
                "personal_users": {"2": False}, "tagged": {},
            }},
        }, "personal")

    def test_schema_tagged_false_mapping_does_not_authorize_tag(self):
        self._assert_malformed_policy_blocks_plan_and_redeem({
            "version": 1, "audiences": {"ops": {
                "personal_users": [], "tagged": {"2": {"tag:lab-a": False}},
            }},
        }, "tagged")

    def test_schema_boolean_version_is_not_version_one(self):
        self._assert_malformed_policy_blocks_plan_and_redeem({
            "version": True, "audiences": {"ops": {
                "personal_users": ["2"], "tagged": {},
            }},
        }, "personal")

    def test_invalid_policy_shapes_and_duplicate_keys_fail_closed(self):
        valid_role = {"personal_users": ["2"],
                      "tagged": {"2": ["tag:lab-a"]}}
        bad_cases = (
            {"version": 1, "audiences": []},
            {"version": 1, "audiences": {"ops": []}},
            {"version": 1, "audiences": {"ops": {
                "personal_users": [True], "tagged": {},
            }}},
            {"version": 1, "audiences": {"ops": {
                "personal_users": ["2", "2"], "tagged": {},
            }}},
            {"version": 1, "audiences": {"ops": {
                "personal_users": [], "tagged": {"0": ["tag:lab-a"]},
            }}},
            {"version": 1, "audiences": {"ops": {
                "personal_users": [], "tagged": {"2": [False]},
            }}},
            {"version": 1, "audiences": {"ops": {
                "personal_users": [], "tagged": {"2": ["tag:lab-a", "tag:lab-a"]},
            }}},
            {"version": 1, "audiences": {"ops": {
                "personal_users": [], "tagged": {"2": ["lab-a"]},
            }}},
            {"version": 1, "audiences": {"ops": valid_role,
                                        "other": {"personal_users": "2",
                                                  "tagged": {}}}},
            '{"version":1,"audiences":{"ops":{"personal_users":["2"],'
            '"personal_users":["2"],"tagged":{"2":["tag:lab-a"]}}}}',
        )
        for bad in bad_cases:
            with self.subTest(policy=bad):
                self._assert_malformed_policy_blocks_plan_and_redeem(
                    bad, "personal"
                )

    def test_invalid_api_argument_types_are_gate_errors(self):
        self.policy.write_text(json.dumps({
            "version": 1, "audiences": {"ops": {
                "personal_users": ["2"], "tagged": {},
            }},
        }))
        for audience, user, tags, ttl in (
            ("ops", "2", [True], 300),
            ("ops", 2, [], 300),
            ("ops", "2", [], True),
            ("ops", "2", [], 5.5),
            (["ops"], "2", [], 300),
        ):
            with self.subTest(audience=audience, user=user, tags=tags, ttl=ttl):
                with self.assertRaises(GateError):
                    self.gate.plan(audience, "personal", user, tags, ttl)
        _, token, _ = self.gate.plan("ops", "personal", "2", [], 300)
        for args in ((None, "ops", "personal", "2", []),
                     (token, "ops", "personal", 2, []),
                     (token, "ops", "personal", "2", [False])):
            with self.subTest(args=args):
                with self.assertRaises(GateError):
                    self.gate.redeem(*args)
        self.assertEqual(self.issuer.calls, [])

    def test_malformed_policy_during_mint_revokes_created_key(self):
        self.issuer = BlockingIssuer(self.clock)
        self.gate = EnrollmentGate(self.db, self.policy, self.issuer, self.clock)
        grant_id, token, _ = self.gate.plan("alice-ops", "personal", "1", [], 300)
        outcome = {}

        def redeem():
            try:
                outcome["key"] = self.gate.redeem(
                    token, "alice-ops", "personal", "1", []
                )
            except GateError as exc:
                outcome["error"] = str(exc)

        worker = threading.Thread(target=redeem)
        worker.start()
        self.assertTrue(self.issuer.minted.wait(5))
        self.policy.write_text(json.dumps({
            "version": 1, "audiences": {"alice-ops": {
                "personal_users": "1", "tagged": {},
            }},
        }))
        self.issuer.release_mint.set()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertNotIn("key", outcome)
        self.assertEqual(self.issuer.expired, ["1"])
        self.assertEqual(self.gate.status(grant_id)["status"], "revoked")

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
        self.assertEqual(self.gate.status(grant_id)["status"], "revoked")

    def test_invalid_key_secret_is_revoked_and_not_returned(self):
        grant_id, token, _ = self.gate.plan("alice-ops", "personal", "1", [], 300)
        self.issuer.bad_secret = True
        with self.assertRaises(GateError):
            self.gate.redeem(token, "alice-ops", "personal", "1", [])
        self.assertEqual(self.issuer.expired, ["1"])
        self.assertEqual(self.gate.status(grant_id)["status"], "revoked")

    def test_policy_revoke_during_mint_never_discloses_key(self):
        self.issuer = BlockingIssuer(self.clock)
        self.gate = EnrollmentGate(self.db, self.policy, self.issuer, self.clock)
        grant_id, token, _ = self.gate.plan("alice-ops", "personal", "1", [], 300)
        outcome = {}

        def redeem():
            try:
                outcome["key"] = self.gate.redeem(
                    token, "alice-ops", "personal", "1", []
                )
            except GateError as exc:
                outcome["error"] = str(exc)

        worker = threading.Thread(target=redeem)
        worker.start()
        self.assertTrue(self.issuer.minted.wait(5))
        self.policy.write_text('{"version":1,"audiences":{}}')
        self.issuer.release_mint.set()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertNotIn("key", outcome)
        self.assertIn("revoked", outcome["error"])
        self.assertEqual(self.issuer.expired, ["1"])
        self.assertEqual(self.gate.status(grant_id)["status"], "revoked")
        self.assertEqual(self.gate.status(grant_id)["key_id"], "1")

    def test_revocation_failure_is_durable_and_not_disclosed(self):
        self.issuer = BlockingIssuer(self.clock)
        self.issuer.expire_fail = True
        self.gate = EnrollmentGate(self.db, self.policy, self.issuer, self.clock)
        grant_id, token, _ = self.gate.plan("alice-ops", "personal", "1", [], 300)
        outcome = {}

        def redeem():
            try:
                outcome["key"] = self.gate.redeem(
                    token, "alice-ops", "personal", "1", []
                )
            except GateError as exc:
                outcome["error"] = str(exc)

        worker = threading.Thread(target=redeem)
        worker.start()
        self.assertTrue(self.issuer.minted.wait(5))
        self.policy.write_text('{"version":1,"audiences":{}}')
        self.issuer.release_mint.set()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertNotIn("key", outcome)
        self.assertIn("operator review", outcome["error"])
        self.assertEqual(self.issuer.expired, ["1"])
        reopened = EnrollmentGate(self.db, self.policy, self.issuer, self.clock)
        self.assertEqual(reopened.status(grant_id)["status"], "revocation_open")
        self.assertEqual(reopened.status(grant_id)["key_id"], "1")
        with self.assertRaises(GateError):
            reopened.redeem(token, "alice-ops", "personal", "1", [])

    def test_revocation_intent_is_durable_before_external_expire(self):
        self.issuer = BlockingIssuer(self.clock)
        self.issuer.block_expire = True
        self.gate = EnrollmentGate(self.db, self.policy, self.issuer, self.clock)
        grant_id, token, _ = self.gate.plan("alice-ops", "personal", "1", [], 300)
        outcome = {}

        def redeem():
            try:
                outcome["key"] = self.gate.redeem(
                    token, "alice-ops", "personal", "1", []
                )
            except GateError as exc:
                outcome["error"] = str(exc)

        worker = threading.Thread(target=redeem)
        worker.start()
        self.assertTrue(self.issuer.minted.wait(5))
        self.policy.write_text('{"version":1,"audiences":{}}')
        self.issuer.release_mint.set()
        self.assertTrue(self.issuer.expiring.wait(5))
        reopened = EnrollmentGate(self.db, self.policy, self.issuer, self.clock)
        self.assertEqual(reopened.status(grant_id)["status"], "revocation_open")
        self.assertEqual(reopened.status(grant_id)["key_id"], "1")
        self.issuer.release_expire.set()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertNotIn("key", outcome)
        self.assertEqual(reopened.status(grant_id)["status"], "revoked")

    def test_malformed_cli_response_and_failed_revoke_need_review(self):
        class MalformedHeadscale(HeadscaleCLI):
            def _run(self, args):
                if args[1] == "create":
                    return {"id": "42"}
                raise GateError("synthetic expire failure")

        gate = EnrollmentGate(
            self.db, self.policy,
            MalformedHeadscale(Path("/unused"), Path("/unused")), self.clock,
        )
        grant_id, token, _ = gate.plan("alice-ops", "personal", "1", [], 300)
        with self.assertRaisesRegex(GateError, "operator review"):
            gate.redeem(token, "alice-ops", "personal", "1", [])
        self.assertEqual(gate.status(grant_id)["status"], "revocation_open")
        self.assertEqual(gate.status(grant_id)["key_id"], "42")

    def test_uncertain_cli_create_without_key_id_needs_review(self):
        class UncertainHeadscale(HeadscaleCLI):
            def _run(self, args):
                raise GateError("synthetic lost create response")

        gate = EnrollmentGate(
            self.db, self.policy,
            UncertainHeadscale(Path("/unused"), Path("/unused")), self.clock,
        )
        grant_id, token, _ = gate.plan("alice-ops", "personal", "1", [], 300)
        with self.assertRaisesRegex(GateError, "operator review"):
            gate.redeem(token, "alice-ops", "personal", "1", [])
        self.assertEqual(gate.status(grant_id)["status"], "revocation_open")
        self.assertIsNone(gate.status(grant_id)["key_id"])

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
