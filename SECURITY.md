# Security policy

## Supported versions

Security fixes apply to the latest commit on `main`.
Older assignment snapshots and release tags are retained for reference and are not maintained.

## Reporting a vulnerability

Use the repository's private vulnerability reporting feature if it is available.
Otherwise, email af4074@nyu.edu with the affected commit, reproduction steps, expected behavior, and impact.
Do not include credentials or disclose an unpatched vulnerability in a public issue.
Reports will be assessed and fixes tested before a public explanation is published.
Compromised credentials should be revoked immediately.

## Verification scope

The CLI checks the artifact hash, an ECDSA signature, and Merkle inclusion or consistency against roots returned by Rekor.
It does not authenticate checkpoint signatures or validate the certificate's identity and trust chain.
A successful result alone does not establish the identity of the signer or protect against a compromised log endpoint.

## Local safeguards

The pre-commit hook scans staged changes using TruffleHog before a commit is created.
Verification is disabled so candidate secrets are blocked without transmitting them to external providers.
Do not bypass the hook to commit a finding.
Remove the secret and rotate it if it was real.
