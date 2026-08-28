# Source provenance

The initial Runtime v1 implementation was extracted from the TinyEdge-authored
private `tinyedge-agent` repository at commit
`74aa0d1e0b0bcdcc167349c1432e9a2ef86d4785` under TIN-381.

The reviewed extraction contains only the generic Python runtime kernel,
deterministic fakes, synthetic fixtures and focused tests. It intentionally
excludes private Git history, benchmark campaigns and evidence, model weights,
datasets, generated artifacts, credentials, machine paths, and Jetson-PI or
LIBERO source.

The extracted runtime has no third-party runtime dependencies. Development
tools are declared separately in `pyproject.toml` and are not imported by the
package.
