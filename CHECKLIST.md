# MCP Server Build Checklist

**Version:** 0.1.0
**Date:** 2026-03-29
**Companion to:** [SPEC.md](SPEC.md) -- MCP Server Security Specification

Copy this checklist into your project's issue tracker or planning document at the start of every new MCP server build.

---

## Phase 1: Before Writing Code

- [ ] Document the threat model (what backend does this server expose? which threats from T1-T16 apply?)
- [ ] Choose thin adapter or thick server (justify in writing if thick; see SPEC Section 2.1)
- [ ] Choose transport: stdio or HTTP (see SPEC Section 6)
- [ ] Define backend authentication mechanism (API key, OAuth, service account; see SPEC Section 7.2)
- [ ] Enumerate all tools with read / write / destructive classification (see SPEC Section 7.3)
- [ ] Document required backend permissions per tool (see SPEC Section 2.5)
- [ ] Identify all trust boundaries and the validation mechanism at each (see SPEC Section 1.3)
- [ ] Define what "done" looks like for security review

---

## Phase 2: For Each Tool

**Schema and Annotations**

- [ ] `input_schema` defined with `type` for every property (SPEC 3.1)
- [ ] `required` fields enumerated (SPEC 3.1)
- [ ] `additionalProperties: false` set (SPEC 3.1)
- [ ] `maxLength` on every string parameter (SPEC 3.1, 3.3)
- [ ] `maxItems` on every array parameter (SPEC 3.3)
- [ ] `enum` used for parameters with known value sets (SPEC 3.1)
- [ ] Tool annotations set: `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint` (SPEC 4.3)

**Description**

- [ ] Description is a factual, concise statement of what the tool does and what it returns (SPEC 4.2)
- [ ] Description contains no LLM instructions ("always", "must", "important", "you should") (SPEC 4.2)
- [ ] Description does not reference other tools by name (SPEC 4.2)
- [ ] Description does not contain system-level instructions or prompt fragments (SPEC 4.2)

**Validation**

- [ ] Server-side validation implemented beyond schema (injection patterns, semantic validity) (SPEC 3.2)
- [ ] Shell metacharacters rejected where parameters could reach shell execution (SPEC 3.2)
- [ ] Path traversal sequences rejected where parameters could become file paths (SPEC 3.2)
- [ ] No tool input interpolated into SQL, shell commands, code evaluation, or GraphQL strings (SPEC 3.5)
- [ ] If tool accepts URLs: SSRF validation applied (scheme, resolved IP, private ranges, metadata endpoints, post-redirect; SPEC 3.4, 8.1)

**Output**

- [ ] Output sanitized: no internal details, no credentials, no stack traces (SPEC 5.1, 5.2)
- [ ] Output size bounded (recommended: 100 KB max; SPEC 5.3)
- [ ] Large result sets paginated, not returned in full (SPEC 5.3)
- [ ] Truncated responses include a truncation indicator (SPEC 5.3)
- [ ] HTML tags stripped from output (SPEC 5.2)
- [ ] Error messages sanitized: no file paths, no SQL, no exception class names (SPEC 5.1)
- [ ] Error messages truncated to 500 characters maximum (SPEC 5.1)
- [ ] Business logic failures return `isError: true`, not JSON-RPC error codes (SPEC 5.5)

---

## Phase 3: Server-Wide

**Rate Limiting**

- [ ] Per-tool rate limits implemented (recommended: 60 calls/minute/tool; SPEC 4.6)
- [ ] Global rate limit implemented as safety backstop (recommended: 300 calls/minute; SPEC 4.6)
- [ ] Rate limit error messages explicitly discourage LLM retry behavior (SPEC 4.6)

**Logging**

- [ ] Structured logging for tool invocations (tool name, parameters, duration, outcome) (SPEC 9)
- [ ] Structured logging for authentication events (SPEC 9)
- [ ] Structured logging for errors (SPEC 9)
- [ ] No credentials in logs at any level, including partial values (SPEC 7.1, 9)
- [ ] Tool inputs sanitized before inclusion in log messages (SPEC 3.5)
- [ ] All diagnostic output to stderr, never stdout (stdio transport; SPEC 6.1)

**Credential Management**

- [ ] Credentials stored in environment variables, not in source code (SPEC 7.1, 7.5)
- [ ] Credentials validated at startup; server refuses to start if missing (SPEC 7.2)
- [ ] Development credentials blocked in production (SPEC 7.2)
- [ ] HTTPS required for all backend calls in production (SPEC 8.3)
- [ ] Different credentials used per environment (dev/staging/prod; SPEC 7.5)

**Architecture**

- [ ] Fail-closed defaults: missing config = refuse to start (SPEC 7.2)
- [ ] No shell execution, no eval, no direct DB access (unless server's explicit purpose; SPEC 2.3)
- [ ] Single outbound integration mechanism, or multiple paths independently validated and audited (SPEC 2.3)
- [ ] All tools are stateless: class methods or pure functions, no mutable instance state (SPEC 2.2)
- [ ] No credentials, sessions, or authorization decisions cached in server memory (SPEC 2.2)

**SSRF Protection (if any tool accepts URLs)**

- [ ] URL scheme validated (HTTPS required by default; SPEC 3.4)
- [ ] Resolved IP checked against private range blocklist (SPEC 3.4, 8.1)
- [ ] Cloud metadata endpoints blocked (169.254.169.254, metadata.google.internal; SPEC 3.4)
- [ ] Localhost variants blocked (SPEC 3.4)
- [ ] IP re-validated after following redirects (SPEC 8.1)
- [ ] Redirect following limited (recommended: max 3; SPEC 8.1)

**Dependencies**

- [ ] Lock file committed (Gemfile.lock, package-lock.json, etc.; SPEC 11.3)
- [ ] Dependency vulnerability scanning configured (bundle audit, npm audit, etc.; SPEC 11.3)
- [ ] Transport isolation: one transport per server process (SPEC 6.3)

---

## Authorization Hardening (HTTP Transport)

- [ ] Tokens are validated for audience (`aud` claim matches server URI) (7.6.1)
- [ ] Resource indicators (RFC 8707) are included in token requests (7.6.2)
- [ ] Client tokens are never forwarded to backend APIs (7.6.3)
- [ ] Proxy servers implement per-client consent registry (7.6.4)
- [ ] Consent cookies use __Host- prefix with Secure/HttpOnly/SameSite=Lax (7.6.4)
- [ ] Third-party credentials do not transit through the MCP client (7.6.5)
- [ ] User identity is verified for third-party auth flows (7.6.5)

---

## Resources, Prompts, and Elicitation

- [ ] Resource URIs are validated (scheme, syntax, path traversal) (16.1)
- [ ] File-scheme resources validate paths against configured roots (16.1)
- [ ] Resource content from external sources has provenance labeling (16.1)
- [ ] Prompt definitions follow description hygiene rules (16.2)
- [ ] Dynamic prompt arguments are sanitized (16.2)
- [ ] Sensitive data collection uses URL mode, not form mode (16.3)
- [ ] Elicitation URLs are bound to specific user sessions (16.3)
- [ ] Sampling requests have iteration limits (16.4)

---

## Server Profile

- [ ] Server profile is identified (thin adapter / HTTP proxy / stateful auth / filesystem-CLI) (15.1-15.4)
- [ ] Profile-specific requirements from Section 15.5 matrix are applied
- [ ] Filesystem/CLI servers run in a sandbox (MUST) (15.4)
- [ ] Stateful auth servers encrypt tokens at rest (15.3)

---

## Phase 4: Before Deployment

**Security Testing**

- [ ] Injection tests pass (SQL, shell, path traversal, GraphQL, log injection; SPEC 3.5)
- [ ] SSRF tests pass (private IPs, metadata endpoints, DNS rebinding via redirect; SPEC 3.4, 8.1)
- [ ] Authentication bypass tests pass (missing credentials, invalid tokens; SPEC 7.1)
- [ ] Rate limit tests pass (per-tool, global, error message content; SPEC 4.6)
- [ ] Output sanitization tests pass (error messages, large responses, credential stripping; SPEC 5)

**Tool Descriptions**

- [ ] All tool descriptions audited for poisoning patterns (SPEC 4.2)
- [ ] Automated scan for flagged patterns: "you must", "always", "never", "ignore previous", "system:", "important:" (SPEC 4.2)

**Container and Infrastructure**

- [ ] Container runs as non-root with minimal permissions (SPEC 2.5)
- [ ] Network access restricted to required backends only (SPEC 8.2)
- [ ] Resource limits configured (memory, CPU)
- [ ] TLS certificate verification enabled on all outbound connections (SPEC 8.3)
- [ ] TLS 1.2 minimum enforced; TLS 1.0 and 1.1 rejected (SPEC 8.3)

**Operations**

- [ ] Monitoring and alerting configured
- [ ] Incident response procedure documented
- [ ] Key rotation procedure documented and tested (SPEC 7.2)
- [ ] Dependency vulnerability scan is clean (SPEC 11.3)
- [ ] Backend enforces its own authorization independently of the MCP server (SPEC 2.4, Layer 4)
