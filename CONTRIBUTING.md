# Contributing

## Workflow

1. Fork the repository and create a focused feature branch.
2. Keep each change small enough to review.
3. Run the relevant build and validation commands locally.
4. Open a pull request against the project repository; do not commit directly to `main`.

Suggested branch names:

- `feature/<short-name>`
- `fix/<short-name>`
- `docs/<short-name>`

## Pull-request expectations

- Explain the user-visible behavior and the reason for the change.
- List the validation performed.
- Keep unrelated refactors out of the same pull request.
- State any known limitation rather than hiding it.
- Do not include generated build output unless the maintainers request it.

## Security and privacy

This is a security project. Contributions must use synthetic or fully authorized data during development. Never commit credentials, private keys, access tokens, service-account files, production traffic captures, or unredacted evidence.

Report security vulnerabilities privately as described in [SECURITY.md](./SECURITY.md).

## Code style

Follow the conventions already present in the component being changed. Prefer deterministic security decisions, explicit error states, and clear source attribution over opaque behavior.
