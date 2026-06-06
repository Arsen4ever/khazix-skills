# Hardening Notes

This branch preserves the five upstream skill names and their main workflows
while tightening security-sensitive defaults.

- Upstream repository: `KKKKhazix/khazix-skills`
- Upstream commit: `9c315d7a71776dae5139b3f717a53e89b7b835c1`
- Local branch: `codex/hardened-global`

Key changes:

- `aihot`: treats API fields as untrusted data and forbids remote installer execution.
- `hv-analysis`: uses an isolated virtual environment and blocks PDF-time resource fetching.
- `khazix-writer`: preserves style guidance without impersonation or default third-party attribution.
- `neat-freak`: limits default scope to the current project and requires explicit authorization for memory, global configuration, and file deletion.
- `storage-analyzer`: defaults to reversible trash operations, hardens inline JSON and the local HTTP service, and gates permanent deletion behind explicit startup and browser confirmation.
