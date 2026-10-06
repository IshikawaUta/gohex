# GoHex — legal & ethics

## License

GoHex is licensed under the [Apache License 2.0](../LICENSE). Copyright
"(c) 2026, GoHex Contributors". Third-party dependencies keep their own
licenses (Go module and npm trees; see `go.mod` and
`frontend/package.json`).

## Authorized use only

GoHex is provided **only** for:

- systems and data **you own**, or
- systems and data for which you hold **documented written authorization**
  (e.g., your employer's incident-response mandate, a client engagement
  letter, a court order, or a lawful consent form).

Unauthorized access to computer systems or data may be a crime in your
jurisdiction. You are responsible for determining that your use is lawful and
for complying with your local law, employer policy, and professional codes of
conduct (e.g., ACPO/NIST forensic principles).

## What GoHex deliberately is not

GoHex contains **no**:

- anti-forensic features (timestomping, log deletion, artifact wiping),
- full-disk or free-space shredding beyond ordinary file edits the user
  performs on data they are authorized to modify,
- password, encryption, or credential bypass,
- live RAM editing or credential extraction,
- stealth, persistence, keylogging, or remote-control capabilities,
- malware of any kind.

Requests for such features — in issues, pull requests, or support — will be
declined, and a PR introducing them will be rejected. See
[SECURITY.md](../SECURITY.md).

## No telemetry, no default network access

Stage 1 makes **no outbound connections by default**. The update checker is
opt-in and off by default (`GOHEX_UPDATE_CHECK=1` enables it).

## Ethics notices

Modules that parse browser artifacts, memory captures, or crash dumps display
an ethics notice the first time they are opened (stages 3–4). The main
disclaimer shown at first launch must be accepted before the application is
usable.

## Evidence integrity

- Prefer read-only profiles for examination; make working copies before
  editing.
- Record chain of custody: enable and retain the audit log
  (`docs/security.md`), and verify hashes on import/export.
- The software is provided **"as is"**, without warranty of any kind; see the
  Apache-2.0 disclaimer of warranties and limitations of liability in
  [LICENSE](../LICENSE). In particular the authors are not liable for
  evidence mishandling, missed findings, or any consequences of use.

## Export & dual-use considerations

GoHex is a general-purpose data-inspection tool. If you redistribute it, you
are responsible for compliance with applicable export-control and crypto
reporting rules in your jurisdiction (the hashing algorithms used are
standard, widely published, and used for integrity, not secrecy).

## Contact

Security matters: [SECURITY.md](../SECURITY.md).
Everything else: GitHub issues of the project repository.
