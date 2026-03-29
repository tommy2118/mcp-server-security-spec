# Project Instructions

This repository contains the MCP Server Security Specification — a set of
markdown documents with normative security requirements for MCP server
implementations.

## Repository Structure

| File | Purpose |
|------|---------|
| `SPEC.md` | Full specification (16 sections, ~2400 lines) |
| `THREAT_MODEL.md` | Detailed threat analysis companion document |
| `CHECKLIST.md` | Single-page build checklist for MCP server projects |
| `COMPLIANCE_MATRIX.md` | Maps official MCP spec requirements to this spec |
| `CHANGELOG.md` | Tracks all spec changes with source citations |
| `README.md` | Project overview and quick start |

## Writing Conventions

- RFC 2119 normative language: MUST, SHOULD, MAY in uppercase carry normative meaning
- References use `[N]` numbered citation format, defined in SPEC.md Appendix A
- Threats are numbered sequentially (T1, T2, ...) in the threat catalog
- Each SPEC.md section ends with a `#### Section N Checklist` block
- THREAT_MODEL.md entries follow a consistent format: STRIDE/CWE table, description,
  attack scenario, mitigations, and references
- Code examples use Ruby but requirements are language-agnostic

## Rules

- Never change the document version number (SPEC.md header) without explicit instruction
- Never remove existing references; only add new ones or update URLs
- Never reorganize section numbering without explicit instruction
- Keep all documents internally consistent (cross-references, threat numbers, etc.)
- Every quantitative claim must have a citation in Appendix A
- Every spec change must have a corresponding CHANGELOG.md entry under `## [Unreleased]`
