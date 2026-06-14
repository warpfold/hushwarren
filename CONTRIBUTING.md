# Contributing to hushwarren

Thanks for helping make network-level privacy boring and universal. Two
things before your first PR: the engineering bar and the license agreement.

## The license agreement (read this first)

hushwarren is **GPL-3.0-or-later** and dual-licensed: the maintainer also
offers the code under separate commercial license terms. For that model to
work, every contribution needs an explicit grant.

By submitting a contribution you agree to the **hushwarren Contributor
License Agreement**:

1. You certify that the contribution is your own original work (or you have
   the right to submit it) and you license it to the project under
   **GPL-3.0-or-later**.
2. You additionally grant the project maintainer a perpetual, worldwide,
   non-exclusive, royalty-free right to **relicense your contribution under
   other terms, including proprietary/commercial license terms**, alone or
   as part of the project.
3. You retain your own copyright — this is a license grant, not an
   assignment. You can do anything else you like with your own code.

To record your agreement, include this line in every PR description (or in
your commit trailer):

```
I agree to the hushwarren CLA as stated in CONTRIBUTING.md.
```

**PRs without the CLA line will not be merged** — not out of bureaucracy,
but because an un-granted contribution would legally poison the dual-license
model for everyone.

## The engineering bar

- Read `specs/standards.md` — it is binding for every change. The quality
  gate (`cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test --workspace` twice, `cargo deny check licenses`) must pass.
- Dependencies must be permissive (MIT/Apache/BSD-class). `deny.toml`'s
  allowlist is authoritative; a dep that fails it is a design conversation,
  not a config edit.
- The product rule is zero-touch: anything that requires the user to
  configure something for basics to work is a bug, not a feature.
- Privacy claims must be honest (see `docs/privacy-roadmap.md` §5): we do
  not claim what DNS cannot deliver.
- Work-package specs live in `specs/`. Substantial features start with a
  spec, not a PR.
