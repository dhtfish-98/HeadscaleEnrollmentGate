# Local validation

The source is checked with Python 3.12 and 3.14 unit tests. The tests cover one-time issuance across a reopen, concurrent redemption, scope mutation, expiration, policy revocation before and during a paused mint, durable revocation intent, failed revocation, invalid key secret, uncertain or malformed Headscale responses, failed issuance, invalid tags and an observed clock rollback. Packaging runs from the combined local candidate at `Build/发布暂存/HeadscaleEnrollmentGate-v0.1.0-local-candidate`, which contains the central source plus `项目文档` and all license texts. The separated `项目源码` directory alone is not a complete release tree.

The live lab compiles the fixed Headscale commit with Go 1.27.0 and a small original `tsnet` client probe using the Tailscale module fixed by that upstream checkout. It runs a Headscale control service and two synthetic users on `127.0.0.1`, with state, module cache, binaries, logs and receipts below `Build`. It tests:

1. Alice and Bob each register a distinct personal node with the intended user ID.
2. A used key cannot register a second node; the gate's consumed grant cannot be redeemed after reopening SQLite.
3. A grant for Alice cannot be changed to Bob, and a `tag:lab-a` grant cannot be changed to `tag:lab-b`. Separately, a real client advertising `tag:lab-b` with a `tag:lab-a` key is rejected by Headscale without consuming the key.
4. A valid tagged key registers `tag:lab-a` under Headscale's special tagged-device identity.
5. An expired grant mints no key, while an independently expired Headscale key registers no node.
6. Restarting both the gate and Headscale preserves the rejection of consumed and expired grants and a used key.
7. A policy revocation after a real Headscale key is minted but before the gate returns is recorded as `revoked`; the secret is withheld, and the expired key cannot register a client.

The lab runner is `lab/validate_live.py`; it requires a local binary compiled from commit `eeaac680bef26585c8cc1569f949e26d0d6aba80`, that fixed checkout's `config-example.yaml`, and a probe binary compiled from `lab/tsnetprobe.go` in the fixed module. The command inputs and outputs are synthetic. It removes node private state and the Headscale control private key after writing a redacted receipt. No key secret is included in the receipt.

The race-fix run at `Build/验证/HeadscaleEnrollmentGate-20261006/live/run-20261005T224043Z/receipt.json` is **PASS, 12 cases**, SHA-256 `c9c5ce6386134ca511be1ef644de0274c6008580bf7f71a7758787eb68c02919`. The fixed Headscale binary SHA-256 is `02a3910756d85bba21e51deea964513af1d98000a86648649fefd473a8a6fb53`; the probe binary SHA-256 is `ba99226f1929f1565bcbf691c0db0286928e99acbfeffc1bdedc0275c5c00eaa`. Both were compiled with Go 1.27.0. The receipt lists exact source hashes and redacted final node/key states. In particular, the tagged node's user ID is Headscale's special `2147455555`, while the key's issuing user ID is Alice's `1`. A separate pre-fix deterministic reproduction is `Build/验证/HeadscaleEnrollmentGate-20261006/pre-fix-policy-race.json`: the old gate returned the synthetic bearer secret after the policy was revoked during mint.

Python 3.12.13 and 3.14.6 each passed 15 unit tests. Their logs are `Build/验证/HeadscaleEnrollmentGate-20261006/unit-python3.12-race.log` (SHA-256 `2b8f0830a1e26c60a098638a8eeb0af2aec15463bc377bdf53d9dd4dc75fffee`) and `unit-python3.14-race.log` (SHA-256 `65f549ee8a53dce6b0ecb84212176d3011e7fac1c8f42d96f788fef53388f9df`).

The local wheel and sdist were built from the combined tracked candidate. The sdist was compared byte-for-byte against all 16 tracked payload files; `.gitignore` is intentionally absent. The wheel metadata names `dhtfish98` and includes the original Headscale and Tailscale license texts. Installed wheel tests on Python 3.14 and installed sdist tests on Python 3.12 each passed 15 cases. Package hashes and install logs are recorded separately in `Build/验证/HeadscaleEnrollmentGate-20261006/race-fix-review.json`, outside the package.

The independent review must bind the receipt's `source_sha256`, binary hashes, upstream commit and run time to the candidate being assessed. Public CI, a release, a real operator deployment and external eligibility remain unverified.
