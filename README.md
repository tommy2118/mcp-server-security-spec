# MCP Server Security Specification

An opinionated, actionable specification for building **sound, safe, and secure** MCP (Model Context Protocol) servers.

The official MCP specification acknowledges that *"MCP itself cannot enforce these security principles at the protocol level"* and leaves implementation security largely unaddressed. This specification fills that gap with concrete MUST/SHOULD/MAY requirements using [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) normative language.

## Why This Exists

The MCP ecosystem has significant security gaps:

- **72.8%** tool poisoning attack success rate (MCPTox benchmark)
- **82%** of servers susceptible to path traversal
- **43%** vulnerable to command injection
- **30+** CVEs filed in January-February 2026 alone
- **88%** of servers require credentials, but only **8.5%** use OAuth

MCP servers sit between an LLM and backend systems with real authority. The LLM-in-the-loop creates attack surfaces that don't exist in traditional APIs: tool outputs become executable context, error messages become injection vectors, retry behavior becomes adversarial, and the confused deputy problem is the default operating mode.

## Documents

| Document | What it covers |
|----------|---------------|
| [**SPEC.md**](SPEC.md) | The full specification --- 14 sections across 4 parts, each ending with an actionable checklist |
| [**THREAT_MODEL.md**](THREAT_MODEL.md) | 12 threats with STRIDE/CWE classification, attack scenarios, real CVEs, and mitigations |
| [**CHECKLIST.md**](CHECKLIST.md) | Single-page build checklist --- copy this when starting a new MCP server |
| [**COMPLIANCE_MATRIX.md**](COMPLIANCE_MATRIX.md) | Official MCP spec requirements mapped to this spec's sections |

## Spec Structure

### Part I: Foundations
1. **Threat Model and Security Context** --- the LLM-in-the-loop problem, 12-threat catalog, trust boundaries
2. **Architecture Principles** --- thin adapter pattern, stateless design, defense in depth

### Part II: Building Secure Tools
3. **Input Validation and Sanitization** --- schema constraints, SSRF prevention, injection checklist
4. **Tool Design** --- naming, description hygiene, annotations, rate limiting
5. **Output Security** --- error sanitization, ATPA defense, response size limits

### Part III: Transport, Authentication, and Network
6. **Transport Security** --- stdio model, HTTP model, transport isolation
7. **Authentication and Authorization** --- deputy boundary, tool-level auth, confused deputy prevention
8. **Network Security** --- SSRF blocklists, outbound restrictions, TLS enforcement

### Part IV: Operational Security
9. **Logging and Auditing** --- what to log, what never to log, audit trails
10. **Configuration Management** --- fail-closed defaults, environment validation
11. **Dependency Management** --- minimal deps, version pinning, vulnerability scanning
12. **Testing Requirements** --- security test categories, fuzzing, penetration checklist
13. **Deployment Security** --- container hardening, network isolation, resource limits
14. **Operational Procedures** --- incident response, key rotation, monitoring

## Quick Start

If you're building a new MCP server, start with:

1. Read [SPEC.md Part I](SPEC.md) (Sections 1-2) to understand the threat model
2. Copy [CHECKLIST.md](CHECKLIST.md) into your project as your build checklist
3. Reference [SPEC.md Part II](SPEC.md) (Sections 3-5) as you implement each tool
4. Review against the checklist before deployment

## Status

**Version 0.1.0 (Draft)** --- March 2026

This is an initial draft reflecting my opinions on what it takes to build secure MCP servers, informed by the official MCP specification, OWASP MCP Top 10, published CVEs, and security research from Invariant Labs, CyberArk, Palo Alto Unit 42, and others.

Feedback welcome via issues.

## License

This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
