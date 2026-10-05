# HeadscaleEnrollmentGate

HeadscaleEnrollmentGate is an original operator-side admission layer for issuing Headscale pre-authentication keys. A trusted operator approves a narrowly scoped, short-lived grant, then redeems it once to mint an actual Headscale key. The grant fixes the intended user ID or tag set. A changed user, changed tag, expired grant, replay, policy revocation or unexpected Headscale response fails closed. The policy is checked again after Headscale creates a key and before its secret is returned. Only a hash of the grant token and the Headscale key ID are persisted; an approved key secret is returned once.

The gate uses an unmodified Headscale CLI and a local Headscale control socket. Headscale itself remains authoritative for node registration and the key's single-use and expiration checks. A user-owned key has no tags. A tagged key can record an issuing user, but Headscale registers the node under its `tagged-devices` identity; that issuing user is **not** the node owner.

This is an engineering candidate. A controlled local lab showed three synthetic nodes registering under two synthetic users or one tag and checked denial cases. It does not identify a Headscale vulnerability, prove device identity, or establish eligibility for any external program. See [the validation record](VALIDATION.md) for the exact local evidence and how to reproduce it.

## Layout

- [`src/headscale_enrollment_gate/`](../src/headscale_enrollment_gate/), [`tests/`](../tests/) and [`lab/`](../lab/): original gate, unit tests and local Go client probe source.
- [`项目文档/`](./): documentation, provenance and third-party license texts.
- [`.github/workflows/verify.yml`](../.github/workflows/verify.yml): source, package and pinned Headscale integration checks. Its generated artifacts live below `Build/ci` and can be downloaded from the corresponding workflow run after CI succeeds.
- `Build/`: generated binaries, caches, local service state and redacted receipts. It is excluded from the source archive.

No Headscale or Tailscale source files are copied into the gate package. The lab probe imports the pinned Tailscale `tsnet` module when compiled, and its binary stays in `Build`.

## Operator contract

The JSON policy maps an operator-side audience to exact Headscale user IDs and allowed tag sets. It must contain integer `version: 1` and an `audiences` object. Each audience name is 1–128 characters, starts with a letter or digit, and then uses only letters, digits, `.`, `_`, `:`, or `-`. Each role contains exactly a `personal_users` list of positive decimal ID strings without leading zeroes and a `tagged` object mapping those IDs to tag lists. Each tag starts with `tag:` followed by 1–63 letters, digits, `_`, or `-`, with a letter or digit first. Wrong types, duplicate names or list entries, malformed IDs and tags, and invalid roles anywhere in the policy close authorization. The audience string is **not authentication**. Run the CLI only from a trusted automation account; keep the Headscale control socket and policy file inaccessible to untrusted callers. Other Headscale administrators can bypass this admission layer by creating keys directly.

`plan` returns a grant ID and a high-entropy capability token once. `redeem` reads that token from standard input, checks the current policy and durable state, then returns a Headscale auth key once. Do not put either token on a command line or in logs. A failed or interrupted issuance stays closed and requires a new approved grant. If `status` reports `revocation_open`, an operator must inspect the recorded key ID in Headscale, expire any live key, and retain evidence of that action; no secret is disclosed by the gate. The key remains a bearer credential until Headscale consumes or expires it.

See [VALIDATION.md](VALIDATION.md) for the exact local acceptance and receipt. The upstream function and license references are in [ORIGIN.md](ORIGIN.md).
