# MCP Specification Compliance Matrix

**Date:** 2026-03-29
**Spec Version:** 0.1.0

This matrix maps official MCP specification requirements to the MCP Server Security Specification (SPEC.md) and tracks ember-mcp's compliance status.

---

## Tools

| MCP Spec Requirement | Source | This Spec | ember-mcp Status | Notes |
|----------------------|--------|-----------|-------------------|-------|
| Every tool MUST define an `input_schema` | MCP Spec: Tools | 3.1 | Compliant | All 71 tools define input schemas with types and required fields. |
| Validate all tool inputs against schema | MCP Spec: Tools | 3.1, 3.2 | Partial | Schema validation is in place. `additionalProperties: false` is not consistently set. `maxLength` and `maxItems` missing on many parameters. See Gap 4. |
| Implement access controls on tools | MCP Spec: Security | 7.3, 7.4 | Partial | Backend delegates authorization via GraphQL API. No tool-level visibility controls or per-category enable/disable. |
| Rate limit tool invocations | MCP Spec: Security | 4.6 | Not Implemented | No per-tool, per-client, or global rate limiting. See Gap 2. |
| Sanitize tool outputs | MCP Spec: Security | 5.1, 5.2 | Implemented | `ErrorHandling` concern sanitizes error responses. HTML stripping and credential redaction in output formatting. |
| Include tool annotations | MCP Spec: Tools | 4.3 | Not Implemented | No `readOnlyHint`, `destructiveHint`, `idempotentHint`, or `openWorldHint` on any tool. See Gap 1. |
| Tool names MUST be unique within server | MCP Spec: Tools | 4.1 | Compliant | All tools use `ember_` prefix with unique names. |
| Tool descriptions MUST accurately describe behavior | MCP Spec: Tools | 4.2 | Partial | Descriptions exist but have not been audited for instruction-like patterns. See Gap 6. |
| Tools MUST NOT expose sensitive operations without confirmation | MCP Spec: Security | 7.3 | Partial | Destructive tools exist but lack additional authorization gates. Backend enforces authorization. |

---

## Transport

| MCP Spec Requirement | Source | This Spec | ember-mcp Status | Notes |
|----------------------|--------|-----------|-------------------|-------|
| Validate `Origin` header (HTTP transport) | MCP Spec: Transport | 6.2 | N/A | ember-mcp uses stdio transport only. |
| Bind to localhost for local HTTP servers | MCP Spec: Transport | 6.2 | N/A | ember-mcp uses stdio transport only. |
| Use cryptographically secure session IDs | MCP Spec: Transport | 6.2 | N/A | ember-mcp uses stdio transport only. No session IDs. |
| Include `Mcp-Session-Id` header in responses | MCP Spec: Transport | 6.2 | N/A | ember-mcp uses stdio transport only. |
| Implement session expiration | MCP Spec: Transport | 6.2 | N/A | ember-mcp uses stdio transport only. |
| Use TLS in production | MCP Spec: Transport | 6.2, 8.3 | Implemented | HTTPS enforced for backend connections via `validate_configuration!`. |
| Stdio: read from stdin, write to stdout only | MCP Spec: Transport | 6.1 | Compliant | Clean stdio setup in `bin/server`. |
| Stdio: no network listeners | MCP Spec: Transport | 6.1 | Compliant | No HTTP ports or sockets opened. |
| Stdio: diagnostic output to stderr only | MCP Spec: Transport | 6.1 | Compliant | No non-MCP content written to stdout. |
| One transport per server process | MCP Spec: Transport | 6.3 | Compliant | Single stdio transport configured at the call site. |

---

## Authentication

| MCP Spec Requirement | Source | This Spec | ember-mcp Status | Notes |
|----------------------|--------|-----------|-------------------|-------|
| OAuth 2.1 with PKCE for HTTP transport | MCP Spec: Auth | 7.1 | N/A | ember-mcp uses stdio transport only. |
| Bearer tokens in `Authorization` header (HTTP) | MCP Spec: Auth | 7.1 | N/A | ember-mcp uses stdio transport only. |
| Tokens MUST NOT appear in URL query strings | MCP Spec: Auth | 7.1 | N/A | ember-mcp uses stdio transport only. |
| No token passthrough (server uses own credentials) | MCP Spec: Security | 7.4 | Compliant | Server authenticates to backend with its own API key. No client tokens forwarded. |
| Credentials from environment, not source code | MCP Spec: Security | 7.1, 7.5 | Compliant | `ENV.fetch("EMBER_API_KEY")` pattern used throughout. |
| Credentials validated at startup | MCP Spec: Security | 7.2 | Compliant | `validate_configuration!` raises on missing or invalid credentials. |
| Dev credentials blocked in production | MCP Spec: Security | 7.2 | Compliant | `validate_configuration!` rejects API keys starting with `dev-` in production. |
| Credentials MUST NOT be logged | MCP Spec: Security | 7.1, 7.5 | Compliant | No credential logging observed. Minimal logging currently. |
| Credentials MUST NOT be in container images | MCP Spec: Security | 7.1 | Compliant | Credentials injected via environment variables at runtime. |

---

## Logging

| MCP Spec Requirement | Source | This Spec | ember-mcp Status | Notes |
|----------------------|--------|-----------|-------------------|-------|
| Log tool invocations | MCP Spec: Security | 9 | Not Implemented | No structured logging of tool calls. See Gap 3. |
| Log messages MUST NOT contain credentials | MCP Spec: Security | 9 | Compliant | No credentials in logs. Logging is minimal, so the risk surface is small. |
| Log messages MUST NOT contain PII | MCP Spec: Security | 9 | Compliant | Minimal logging currently produces no PII. Structured logging (Gap 3) will need to maintain this. |
| Log security-relevant events | MCP Spec: Security | 9 | Partial | Startup validation errors are surfaced. Runtime errors returned to client but not systematically logged. |

---

## Security Best Practices

| MCP Spec Requirement | Source | This Spec | ember-mcp Status | Notes |
|----------------------|--------|-----------|-------------------|-------|
| Implement sandboxing for server execution | MCP Spec: Security | 13.1 | Partial | Runs in Docker container. Container does not enforce non-root. See deployment hardening. |
| Apply principle of minimal permissions | MCP Spec: Security | 2.5 | Partial | Single API key with broad access. Target state: per-user identity passed to backend. See SPEC 7.4. |
| Validate inputs at every trust boundary | MCP Spec: Security | 3.1 | Implemented | Schema validation on all tools. Backend performs its own validation. |
| Sanitize error messages | MCP Spec: Security | 5.1, 5.5 | Implemented | `ErrorHandling` concern strips paths, SQL, and internal details. Truncates to 500 characters. |
| Prevent SSRF via URL validation | MCP Spec: Security | 3.4, 8.1 | Implemented | `UrlValidation` concern checks scheme, resolves IPs against blocklist, blocks metadata endpoints. |
| Prevent command injection | MCP Spec: Security | 2.3, 3.5 | Implemented | No shell execution in codebase. Thin adapter pattern eliminates the vector. |
| Prevent path traversal | MCP Spec: Security | 2.3, 3.5 | Implemented | No filesystem access in codebase. Thin adapter pattern eliminates the vector. |
| Prevent code injection | MCP Spec: Security | 2.3, 3.5 | Implemented | No `eval`, `instance_eval`, `send` on tool inputs. GraphQL variables used exclusively. |
| Use parameterized queries (not string interpolation) | MCP Spec: Security | 3.5 | Implemented | All GraphQL queries use `$variable` syntax. No string interpolation into queries. |
| Pin dependencies and scan for vulnerabilities | MCP Spec: Security | 11.3 | Partial | Gemfile.lock committed (pinning). No automated vulnerability scanning in CI. See Gap 7. |
| Defend against ATPA (output-based injection) | MCP Spec: Security | 5.4 | Not Implemented | User-generated content flows back unsanitized. No prompt injection pattern scanning on outputs. See Gap 8. |
| Enforce TLS certificate verification | MCP Spec: Security | 8.3 | Implemented | Default Faraday SSL verification. `ssl.verify` not disabled anywhere in codebase. |

---

## Status Legend

| Status | Meaning |
|--------|---------|
| **Compliant** | Requirement fully met. |
| **Implemented** | Functionally implemented; may benefit from hardening. |
| **Partial** | Some aspects addressed; gaps remain. See referenced gap analysis items. |
| **Not Implemented** | Requirement not yet addressed. Active gap. |
| **N/A** | Requirement does not apply to ember-mcp's current architecture (e.g., HTTP-only requirements for a stdio server). |
