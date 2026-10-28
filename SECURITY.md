# Security Policy

## Supported Versions

csrf-sec is in its 0.9 release-candidate line. Security fixes ship as
patch releases (`0.9.Y`) on the latest line; there is no back-porting
to older lines before 1.0.

| Version | Supported |
|---------|-----------|
| `0.9.x` | yes (current) |
| `< 0.9` | no |

When 1.0 ships, the 1.x line will get security fixes as `1.x.Y` patch
releases, and 0.9.x will be supported for three months after it.

## Reporting a Vulnerability

csrf-sec decides whether a state-changing request may proceed, so a
bug in it can be a vulnerability in every application that uses it.
Please **report privately**; do not open a public issue.

### Channel

Email **me@jamesgober.com** with the subject line `[csrf-sec security]`
and a one-line summary.

Include:

- The affected version(s).
- A minimal reproduction: a test, a request sequence, or a token.
- Your assessment of severity and exploitability.
- Whether you intend to file a CVE or GitHub advisory.

### Response timeline

- **Acknowledgement:** within 72 hours.
- **Triage and severity assessment:** within 7 days.
- **Fix:** released as soon as it is verified, typically within 14 days
  for high-severity issues, with a test that failed before the fix.
- **Disclosure:** coordinated with the reporter, after the fix is
  published on crates.io.

### What qualifies

- A request that passes `verify` or `check` without the key or the
  victim's token: a forged token, a token moved to another session or
  scope, a one-time token accepted twice, a token accepted after it
  should be dead (expired, signed by a retired key).
- A request origin decision that passes a cross-site request it should
  refuse, or a configuration that silently turns a check off.
- Timing differences that depend on secret bytes (the key, a subkey,
  the expected tag).
- A panic, overflow, or unbounded allocation reachable from request
  input.
- Secrets in `Debug`, `Display`, or error output.
- Documentation that leads an integrator into an unsafe setup.

If you are not sure whether something qualifies, report it privately.

## Verification

Every pull request and push to `main` runs, on Linux, macOS, and
Windows with stable and the MSRV: the test suite (including an attack
test per threat, property tests per invariant, and fixed token
vectors), bare-metal `no_std` builds, a constant-time smoke test, fuzz
smoke runs, mutation testing of the changed code, `cargo audit`, and
`cargo deny`. The threat model and every security decision are in
[`dev/PLAN.md`](dev/PLAN.md).

## Acknowledgements

Reporters who help fix an issue responsibly are credited in the
release notes (`docs/release/vX.Y.Z.md`) and the GitHub release, unless
they ask not to be.
