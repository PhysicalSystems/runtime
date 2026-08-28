# Contributing

Thank you for improving TinyEdge Runtime.

1. Open or reference a scoped issue before changing a wire contract or safety
   invariant.
2. Branch from `main` and keep each pull request focused.
3. Preserve Runtime v1 contract strings and golden hashes unless the proposal
   explicitly introduces a new version.
4. Add deterministic tests for success, failure and cleanup behavior.
5. Run:

   ```powershell
   python -m pip install -e ".[dev]"
   python -m pytest
   python -m build
   python -m twine check dist/*
   ```

Runtime changes must not add private evidence, credentials, model weights,
machine-specific paths, benchmark implementation, or unreviewed third-party
source. By contributing, you agree that your contribution is licensed under
Apache-2.0.
