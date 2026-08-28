# Release process

Releases are maintainer-controlled and require a scoped TIN issue.

1. Confirm every contract/hash change is explicitly versioned.
2. Run the complete test, build and provenance checks from a clean checkout.
3. Build both sdist and wheel with `python -m build`.
4. Validate artifacts with `python -m twine check dist/*` and install the wheel
   in a fresh environment.
5. Record artifact SHA-256 values and attach them to the release evidence.
6. Create an immutable signed tag and GitHub release.
7. Publish to a package index only with separate explicit release
   authorization and trusted publishing configured.
8. Update consumers to an exact version or immutable artifact identity.

Creating or merging source is not package-index publication authorization.
