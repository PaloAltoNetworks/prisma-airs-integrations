# Prisma AIRS Guardrails for MuleSoft Omni Gateway (work in progress)

A MuleSoft Omni Gateway custom policy, built with the Policy Development Kit (PDK), that scans Model Proxy traffic
with Palo Alto Networks Prisma AIRS (AI Runtime Security, API Intercept) and enforces the verdict inline.

> [!WARNING]
> **Under construction. Do not deploy.** At this stage the policy validates its settings and refuses every request
> with HTTP 503. Coverage, configuration steps and validation results are added as they are measured.

## Layout

| Path | What it is |
|---|---|
| `definition/gcl.yaml` | The policy definition: its settings, as the MuleSoft console shows them |
| `src/` | The PDK wiring (`src/generated/` is generated from `gcl.yaml` at build time) |
| `core/` | The scanning logic as a plain Rust crate with no gateway dependency, unit-tested with `make unit` |
