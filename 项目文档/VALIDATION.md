# Local validation

The source is checked with Python 3.12 and 3.14 unit tests. The tests cover one-time issuance across a reopen, concurrent redemption, scope mutation, expiration, policy revocation, unexpected Headscale metadata, failed issuance, invalid tags and an observed clock rollback. Packaging runs from the combined local candidate at `Build/发布暂存/HeadscaleEnrollmentGate-v0.1.0-local-candidate`, which contains the central source plus `项目文档` and all license texts. The separated `项目源码` directory alone is not a complete release tree.

The live lab compiles the fixed Headscale commit with Go 1.27.0 and a small original `tsnet` client probe using the Tailscale module fixed by that upstream checkout. It runs a Headscale control service and two synthetic users on `127.0.0.1`, with state, module cache, binaries, logs and receipts below `Build`. It tests:

1. Alice and Bob each register a distinct personal node with the intended user ID.
2. A used key cannot register a second node; the gate's consumed grant cannot be redeemed after reopening SQLite.
3. A grant for Alice cannot be changed to Bob, and a `tag:lab-a` grant cannot be changed to `tag:lab-b`. Separately, a real client advertising `tag:lab-b` with a `tag:lab-a` key is rejected by Headscale without consuming the key.
4. A valid tagged key registers `tag:lab-a` under Headscale's special tagged-device identity.
5. An expired grant mints no key, while an independently expired Headscale key registers no node.
6. Restarting both the gate and Headscale preserves the rejection of consumed and expired grants and a used key.

The lab runner is `lab/validate_live.py`; it requires a local binary compiled from commit `eeaac680bef26585c8cc1569f949e26d0d6aba80`, that fixed checkout's `config-example.yaml`, and a probe binary compiled from `lab/tsnetprobe.go` in the fixed module. The command inputs and outputs are synthetic. It removes node private state and the Headscale control private key after writing a redacted receipt. No key secret is included in the receipt.

The fixed run at `Build/验证/HeadscaleEnrollmentGate-20261006/live/run-20261005T222621Z/receipt.json` is **PASS, 11 cases**, SHA-256 `0a64d03796ce1cf616ae562787db033029e2f5b8bcb54be264ce3eb5befbbe47`. The fixed Headscale binary SHA-256 is `02a3910756d85bba21e51deea964513af1d98000a86648649fefd473a8a6fb53`; the probe binary SHA-256 is `ba99226f1929f1565bcbf691c0db0286928e99acbfeffc1bdedc0275c5c00eaa`. Both were compiled with Go 1.27.0. The receipt lists exact source hashes and redacted final node/key states. In particular, the tagged node's user ID is Headscale's special `2147455555`, while the key's issuing user ID is Alice's `1`.

Python 3.12.13 and 3.14.6 each passed 9 unit tests. Their logs are `Build/验证/HeadscaleEnrollmentGate-20261006/unit-python3.12.log` (SHA-256 `98fca78f5a25cd872f2ac7f47e388f424bfb9dcd10b9c151520c53fe01b06cb0`) and `unit-python3.14.log` (SHA-256 `98f5ba13c42b218faf146cb5239e11d1598e3c64aa0fe2e430902be252ae8516`).

The independent review must bind the receipt's `source_sha256`, binary hashes, upstream commit and run time to the candidate being assessed. Package installation, public CI, a release, a real operator deployment and external eligibility remain unverified.
