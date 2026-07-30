# Sunshine client fingerprint rules

This repository is the public, auditable source for Sunshine's warning-only
client fingerprint feed.

The rules do not authenticate clients and never block a connection. A match
only allows Sunshine's user-session tray provider to warn the host user that a
client is highly likely to be an unknown, unauditable, or license-infringing
derivative.

## Published files

- `rules/rules.json` is the human-reviewed rule list.
- `payload.json` is the exact generated payload covered by the signature.
- `stable.json` is the envelope downloaded by Sunshine.
- `certs/rules-signing.pem` is the public certificate pinned by Sunshine Core.
- `revision.txt` is the monotonically increasing feed revision.

Stable feed URL:

```text
https://raw.githubusercontent.com/AlkaidLab/sunshine-client-fingerprint-rules/main/stable.json
```

## Updating rules

Edit only `rules/rules.json` and submit the change for review. The publish
workflow increments the revision, refreshes the 90-day validity window, signs
the exact payload bytes, and commits the generated files. A scheduled run
refreshes the feed before it expires even when the rule list does not change.

The signing private key is stored only as the repository Actions secret
`RULE_SIGNING_KEY_PEM`. It must never be committed or included in workflow
artifacts.

Rules are intentionally constrained to exact, bounded string predicates. The
Sunshine Core independently verifies the signature, expiry, schema, revision,
and supported warning-only operations before activating a feed.
