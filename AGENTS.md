# tinyedge-runtime contributor instructions

This repository owns TinyEdge's public execution kernel, versioned runtime
contracts, adapter protocols, deterministic strategy engines, primitive runtime
telemetry, test fakes and conformance fixtures.

It must not import implementation from `tinyedge-agent`, `tinyedge-platform` or
`tinyedge-benchmarks`. Host authentication, artifact materialization, concrete
device drivers, daemon supervision and fleet communication belong to Agent.
Campaign design, scientific evaluation, statistics and evidence sealing belong
to Benchmarks.

## Before changing code

- Read the relevant TIN issue and use `lienert/tin-<n>-<slug>` branches.
- Inspect Git status and preserve unrelated changes.
- Treat contract strings, canonical bytes and golden hashes as versioned API.
- Additive fields require a new contract version because v1 rejects unknown
  keys by design.

## Verification

- Run `python -m pytest` for every change.
- Run `python -m build` and `python -m twine check dist/*` for packaging changes.
- Runtime code must remain device-free and must not require network,
  credentials, model weights or private evidence for its tests.
- Do not publish packages or create physical/device evidence without explicit
  release authorization.
