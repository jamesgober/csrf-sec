<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>csrf-sec</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

---

## [0.2.0] - 2026-10-21

Design lock. The public API and the token format are written down; no
functional code yet.

### Added

- `docs/API.md`: the locked public surface. Tier 1 (`Csrf::new`, `issue`,
  `verify`, `check`), Tier 2 (`Binding`, `issue_with`, `verify_with`,
  `check_with`, the builder, rotation), Tier 3 (`issue_at`, `verify_at`,
  `check_at`, `PadSource`), `RequestFacts` and the layer-1 decision, modes,
  one-time tokens (`NonceStore`, `MemoryStore`), `Verdict`, `Reason` with
  severities, `Error`, constants, feature flags, cookie guidance, and the token
  format byte by byte.
- `dev/PLAN.md` decisions D-008 to D-026; every open decision answered.

### Changed

- The MAC input length-prefixes the session id and scope (the plain
  concatenation in `0.1.0`'s plan was ambiguous), and domain separation moves
  from a text prefix into per-key subkeys.
- One-time tokens are signed tokens with a nonce, checked before the store is
  touched, instead of a stored random value.
- `issue` returns `Result<Token, Error>` with an inline, allocation-free token.

---

## [0.1.0] - 2026-10-21

The scaffold and the plan. No functional code yet.

### Added

- Crate manifest (edition 2024, MSRV 1.85, no dependencies), `Apache-2.0 OR MIT`
  license, README, REPS, CI (Linux, macOS, Windows on stable and 1.85; audit
  and deny), `deny.toml`, `clippy.toml`, `rustfmt.toml`, `.gitattributes`.
- `dev/PLAN.md` (purpose, scope, the three layers of defence, token design,
  keys and rotation, verdicts, threats T1-T15, architecture, ecosystem, open
  decisions, decision log), `dev/DIRECTIVES.md`, and `dev/ROADMAP.md`.

[Unreleased]: https://github.com/jamesgober/csrf-sec/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jamesgober/csrf-sec/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/csrf-sec/releases/tag/v0.1.0
