# Product and repository boundary

TinyEdge Runtime is the public execution core, not the entire TinyEdge product.

| Repository | Owns | Does not own |
|---|---|---|
| `tinyedge-runtime` | Contracts, adapter protocols, execution engines, strategy APIs, raw bounded telemetry, fakes and conformance | Credentials, fleet operations, benchmark claims or concrete managed hardware |
| `tinyedge-agent` | Authenticated device host, artifact trust, daemon lifecycle, capabilities, concrete adapters, watchdogs and telemetry delivery | Runtime kernel semantics or benchmark statistics |
| `tinyedge-platform` | Job intent, API, console, authentication, fleet and cloud control plane | Device execution implementation |
| `tinyedge-benchmarks` | Campaigns, tasks, seeds, protocols, evaluation, statistics and sealed evidence | Runtime implementation |

The dependency direction is deliberate:

```text
platform --job intent--> agent --pinned package--> runtime
benchmarks --released contracts/conformance--> agent or runtime
runtime --imports--> Python standard library
```

Runtime executes an explicit strategy. A managed optimizer may choose the
strategy and parameters, but that selection intelligence does not need to live
in the public kernel. Generic strategies can ship here; hardware-specific or
commercial integrations can ship as separate adapter packages.
