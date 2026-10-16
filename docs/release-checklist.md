# Release checklist

Permit versions from `info.rkt` (`version` field), the changelog, and an
annotated Git tag. A release is the package plus signed source artifacts;
work through every step in order and record the evidence in the release
notes.

## 1. Freeze and verify

1. `git pull` and confirm `main` is exactly the commit the release tags.
2. Run the full required checks from [CONTRIBUTING.md](../CONTRIBUTING.md):

   ```bash
   raco pkg install --auto --no-docs --link
   raco make permit/main.rkt permit/cli.rkt permit-doc/scribblings/permit.scrbl
   raco test -p permit
   racket test-vectors/v1/generate.rkt
   git diff --exit-code -- test-vectors/v1
   ```

3. Build the C conformance runner and run it against the corpus:

   ```bash
   make -C conformance/c
   conformance/c/permit-conformance test-vectors/v1
   ```

4. Install the package fresh from the repository (`raco pkg install` from a
   clean clone, not the working tree) and run `raco test -p permit` again.
   A release must never ship only-in-the-working-tree state.
5. Confirm CI is green on the release commit, including the Racket matrix,
   the quality job, and the C conformance job.

## 2. Version and changelog

1. Set the `version` field in `info.rkt`.
2. Date the `Unreleased` changelog section with the version and today's
   date. Every user-visible change since the last tag must appear; add the
   concrete evidence actually exercised (platforms, Racket versions,
   vector checks, external implementations).
3. Protocol v1 vector changes are append-only. If a release would move an
   existing vector, stop: that is a protocol change and needs its own
   documented decision.

## 3. Signed source release

The source archive is signed with the designated Permit source-release
Ed25519 key. That key is a fourth trust domain, separate from credential
signing keys and from any product's update keys; it lives in the operator
keystore (`~/Sync/Keys`), not in the repository. Provision it once with
`raco permit keygen --purpose ...`-style hygiene before the first signed
release.

```bash
version=X.Y.Z
git archive --format=tar.gz --prefix="permit-$version/" "v$version" \
    -o "permit-$version.tar.gz"
shasum -a 256 "permit-$version.tar.gz" > "permit-$version.tar.gz.sha256"
openssl pkeyutl -sign -rawin -inkey <release-private-key> \
    -in "permit-$version.tar.gz" -out "permit-$version.tar.gz.sig"
# Verify from a clean shell: -in must be a file, stdin fails silently.
openssl pkeyutl -verify -rawin -pubin -inkey <release-public-key> \
    -in "permit-$version.tar.gz" -sigfile "permit-$version.tar.gz.sig"
```

## 4. Tag and publish

1. Commit the version bump and changelog on `main`.
2. Create an annotated tag `vX.Y.Z` with a message naming the release
   highlights, and push the commit and the tag.
3. Publish the GitHub release marked Latest with: the changelog section,
   the source archive, the checksum, the detached signature, and the
   verification command from step 3.
4. Check the package catalog entry after release: version updated, farm
   build green, and the rendered manual current.
5. Record in the release notes which non-Racket implementation (for
   example the C conformance runner at the tagged commit) passed the
   corpus, per the [roadmap](../ROADMAP.md) readiness items.
