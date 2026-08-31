# Release process

Releases are maintainer-controlled and require a scoped TIN issue.

The production package index is PyPI. Publication is performed only by
`.github/workflows/release.yml` through the protected `pypi` environment and
PyPI Trusted Publishing; maintainers do not upload with long-lived API tokens.

1. Confirm every contract/hash change is explicitly versioned.
2. Run the complete test, build and provenance checks from a clean checkout.
3. Build both sdist and wheel with `python -m build`.
4. Validate artifacts with `python -m twine check dist/*` and install the wheel
   in a fresh environment.
5. Record artifact SHA-256 values and attach them to the release evidence.
6. Create a signed tag, verify it locally, and create a draft GitHub release.
   Attach the wheel, sdist and `SHA256SUMS.txt` before publishing the release.
   Repository release immutability must be enabled before publication.
7. Publish to a package index only with separate explicit release
   authorization and trusted publishing configured.
8. Update consumers to an exact version or immutable artifact identity.

Creating or merging source is not package-index publication authorization.

The wheel is the Python execution library. Public JSON schemas and golden
fixtures remain version-controlled release source artifacts and are included
in the sdist and tagged GitHub source; they are not Python package resources in
Runtime 0.1.
