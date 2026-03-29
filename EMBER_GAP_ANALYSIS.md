# ember-mcp Gap Analysis

**MCP Server Security Specification**
**Date:** 2026-03-29
**Spec Version:** 0.1.0

---

## Summary

ember-mcp is already well-positioned. The thin adapter pattern, SSRF protection, error sanitization, and config validation put it ahead of 80%+ of the MCP ecosystem. These 10 items bring it into full spec compliance.

---

## Gap 1: Tool Annotations

**Spec Reference:** Section 4.3 (Tool Annotations)

**Current State:** ember-mcp tools do not include `readOnlyHint`, `destructiveHint`, `idempotentHint`, or `openWorldHint` annotations. Tools are registered with a name, description, and input schema only.

**Required State:** Every tool MUST include accurate annotations per the spec. These annotations communicate behavioral metadata to the client and LLM: whether a tool modifies state, whether it is safe to retry, and whether it interacts with external systems. Clients may use annotations to skip user confirmation for read-only tools or to warn before destructive operations.

**Effort:** S
**Priority:** Medium

**Implementation Notes:**
- Add an `annotations` hash to each tool class, alongside the existing `input_schema`.
- Use the classification table in SPEC Section 4.3 as the source of truth: Search/List/Get tools get `readOnlyHint: true, destructiveHint: false, idempotentHint: true`; Create tools get `readOnlyHint: false, destructiveHint: false, idempotentHint: false`; Delete/Archive tools get `destructiveHint: true`; Upload/Export tools get `openWorldHint: true`.
- Audit all 71 tools against the table. This is mechanical work: most tools fall into one of 6 categories.
- Consider adding a shared concern or base class method that derives default annotations from a declared category (e.g., `tool_category :read_only`), with per-tool override capability.

---

## Gap 2: Rate Limiting

**Spec Reference:** Section 4.6 (Rate Limiting)

**Current State:** No rate limiting exists. An LLM retry loop can generate unlimited calls to any tool. There is no per-tool limit, no per-client limit, and no global backstop.

**Required State:** The server MUST implement per-tool rate limits and a global rate limit. Recommended defaults: 60 calls per minute per tool, 300 calls per minute global. Rate limit error messages MUST explicitly discourage LLM retry behavior.

**Effort:** M
**Priority:** Critical

**Implementation Notes:**
- Add a `RateLimiting` concern or middleware that wraps tool execution.
- Use an in-memory counter (Hash of tool name to call timestamps or a sliding window counter). Stateless between restarts is acceptable for stdio transport since each session is a single process.
- Track calls per tool per minute. When a limit is hit, return an `isError: true` response with the recommended phrasing from SPEC 4.6: "Rate limit exceeded. This is a temporary restriction, not an error in your request. Do not retry this request. Wait for the user to initiate a new action."
- Add a global counter that caps total invocations across all tools.
- Make limits configurable via environment variables (e.g., `RATE_LIMIT_PER_TOOL=60`, `RATE_LIMIT_GLOBAL=300`) so they can be tuned per environment.
- This is the highest-risk gap. Without rate limiting, a single transient backend error can trigger an unbounded retry loop, burning LLM tokens and backend API quota (denial of wallet, T9).

---

## Gap 3: Structured Logging

**Spec Reference:** Section 9 (Monitoring and Logging)

**Current State:** Minimal logging. Tool invocations, errors, and auth events are not systematically captured. No structured format.

**Required State:** The server MUST produce structured JSON logs for tool invocations (tool name, parameters, duration, outcome), errors (sanitized), and authentication events. Logs MUST go to stderr (stdio transport). Logs MUST NOT contain credentials or PII.

**Effort:** M
**Priority:** High

**Implementation Notes:**
- Add a `Logging` concern that wraps tool calls. Before execution: log tool name, sanitized parameters, timestamp. After execution: log duration, success/failure, response size.
- Use JSON format for structured log entries. Each entry should include: `timestamp`, `level`, `tool`, `event` (invocation/success/error/rate_limit), `duration_ms`, and sanitized `params`.
- Sanitize parameters before logging: strip or redact any values that could contain credentials, truncate long string values, and escape newlines/control characters to prevent log injection (SPEC 3.5).
- Write all log output to stderr via `$stderr` or `STDERR`. Never write logs to stdout (SPEC 6.1).
- Consider adding a correlation ID per tool invocation for tracing.
- Auth events to log: startup credential validation (success/failure), backend connection errors.

---

## Gap 4: Input Schema Tightening

**Spec Reference:** Section 3.1 (Schema Validation), Section 3.3 (Size Limits)

**Current State:** Many tools define `input_schema` with types and required fields, but do not set `additionalProperties: false`, `maxLength` on string parameters, or `maxItems` on array parameters. This allows the LLM to pass unexpected fields and unbounded input sizes.

**Required State:** Every tool's `input_schema` MUST set `additionalProperties: false`. Every string parameter MUST have a `maxLength`. Every array parameter MUST have `maxItems`. Enum should be used for parameters with known value sets.

**Effort:** S
**Priority:** High

**Implementation Notes:**
- Audit all 71 `input_schema` definitions. This is a systematic pass, not a design exercise.
- Add `additionalProperties: false` to every schema that lacks it.
- Add `maxLength: 255` as a sensible default for short string fields (names, titles, IDs). Use `maxLength: 5000` or similar for longer text fields (descriptions, content). Use `maxLength: 50` for ID fields.
- Add `maxItems` to array parameters. Recommended: `maxItems: 100` for list inputs unless the tool has a specific reason to accept more.
- Add `enum` where applicable: status fields, sort directions, filter types.
- Consider writing a rake task or test that asserts every tool's schema includes `additionalProperties: false` and every string property has `maxLength`, to prevent regressions.

---

## Gap 5: Output Size Limits

**Spec Reference:** Section 5.3 (Response Size Limits)

**Current State:** No truncation of large GraphQL responses. A tool returning a large course tree, a full list of enrollments, or deeply nested curriculum data could exceed reasonable bounds, consuming LLM context tokens and increasing ATPA surface area.

**Required State:** Tool responses MUST be bounded (recommended: 100 KB max). Large result sets MUST be paginated. Truncated responses MUST include a truncation indicator.

**Effort:** S
**Priority:** Medium

**Implementation Notes:**
- Add a response size check in the base tool class or a shared concern, applied after formatting and before returning.
- If the formatted response exceeds 100 KB, truncate and append: `"[Truncated: response exceeded 100 KB. Use pagination parameters to retrieve smaller result sets.]"`
- Verify that list tools (search, list) already use pagination from the GraphQL API. If any return unbounded results, add `first`/`limit` defaults.
- Measure actual response sizes for the largest tools (course trees, enrollment lists) to calibrate the limit.

---

## Gap 6: Tool Description Audit

**Spec Reference:** Section 4.2 (Tool Description Hygiene)

**Current State:** Tool descriptions have not been systematically audited for instruction-like patterns. Some descriptions may contain phrases like "always", "must", "important", or references to other tools by name, which the LLM interprets as behavioral directives rather than factual documentation.

**Required State:** All tool descriptions MUST be factual statements of what the tool does and what it returns. No instructions, no cross-tool references, no urgency markers.

**Effort:** S
**Priority:** High

**Implementation Notes:**
- Write a rake task that scans all tool descriptions for flagged patterns: "you must", "always", "never", "ignore previous", "system:", "important:", "note:", "remember:", "before calling", "after calling", and any tool name references (strings matching `ember_`).
- Run the task against all 71 tools.
- Rewrite any flagged descriptions to be purely descriptive. For example, change "Always provide the course_id. You must call ember_get_course first." to "Retrieves enrollment data for a specific course. Returns enrollment count, status breakdown, and student list."
- Add the rake task to CI so new descriptions are automatically checked.
- This is high priority because description issues are invisible during normal development and testing but directly affect LLM behavior in production.

---

## Gap 7: Dependency Vulnerability Scanning

**Spec Reference:** Section 11.3 (Supply Chain Security)

**Current State:** No automated `bundle audit` or equivalent vulnerability scanning in CI. Dependencies are pinned via Gemfile.lock, but known vulnerabilities in pinned versions are not automatically detected.

**Required State:** Automated dependency vulnerability scanning MUST run in CI. The build SHOULD fail on critical or high vulnerabilities.

**Effort:** S
**Priority:** High

**Implementation Notes:**
- Add `bundler-audit` gem to the development group in Gemfile.
- Add a `bundle audit check --update` step to the CI pipeline and/or Makefile.
- Configure CI to fail on critical and high vulnerabilities. Medium and low can be reported but not block the build initially.
- Consider also adding `ruby_audit` for Ruby interpreter CVEs.
- Run `bundle audit` once immediately to establish a baseline and fix any existing vulnerabilities.
- This is especially important given CVE-2025-6514 in `mcp-remote` (cited in SPEC Section 1.2, T12). The MCP ecosystem's libraries are young and rapidly evolving, which increases supply chain risk.

---

## Gap 8: ATPA Defense

**Spec Reference:** Section 5.4 (Preventing Output-Based Injection)

**Current State:** User-generated content from the Ember LMS (course descriptions, review comments, content layers, curriculum notes) flows back to Claude unsanitized. This content is authored by end users and content creators. A malicious or compromised entry could contain instructions that the LLM follows.

**Required State:** The server SHOULD reduce the ATPA attack surface by stripping known prompt injection patterns from user-generated content, using structured JSON output for content-heavy responses, and preferring IDs and metadata over raw free-text when the tool's purpose does not require full text.

**Effort:** M
**Priority:** High

**Implementation Notes:**
- Identify which tools return user-generated content. Primary candidates: tools returning course descriptions, review comments, content layer text, curriculum notes, user profile bios.
- Add output scanning for known prompt injection patterns in user-generated content fields. Patterns to strip or flag: "ignore previous", "system:", "you are a", "new instructions", "disregard above", "IMPORTANT:". This is an imperfect heuristic but catches unsophisticated attacks.
- Ensure content-heavy responses use structured JSON with labeled fields (e.g., `"description": "..."`) rather than embedding user text into prose paragraphs. The spec notes that structured formats give the LLM stronger signals about data boundaries.
- Consider adding a `_content_origin: "user_generated"` metadata field to responses containing user-authored content.
- This does not fully mitigate ATPA (the fundamental vulnerability is in the LLM), but it meaningfully reduces the attack surface.

---

## Gap 9: Health Check

**Spec Reference:** Section 13.4 (Operational Requirements)

**Current State:** No mechanism to verify GraphQL backend connectivity. If the Ember LMS API is unreachable, the server starts successfully and every tool call fails individually, generating error responses that may trigger LLM retry loops.

**Required State:** The server SHOULD verify backend connectivity at startup or provide a health check mechanism for monitoring.

**Effort:** S
**Priority:** Medium

**Implementation Notes:**
- Option A: Add a lightweight connectivity check to `validate_configuration!` that sends a minimal GraphQL introspection query (e.g., `{ __typename }`) to the Ember API at startup. If the backend is unreachable, the server fails to start with a clear error. This is the fail-fast approach consistent with the existing credential validation pattern.
- Option B: Add an `ember_health_check` tool that returns backend connectivity status, API response time, and server version. This is useful for ongoing monitoring but does not prevent startup with a broken backend.
- Recommended: implement both. Option A prevents a broken server from entering the tool loop. Option B provides runtime observability.
- The health check tool, if implemented, should be annotated `readOnlyHint: true, idempotentHint: true`.

---

## Gap 10: openWorldHint on External Tools

**Spec Reference:** Section 4.3 (Tool Annotations)

**Current State:** Upload and export tools interact with external systems (file storage, SCORM package endpoints, PDF generation services) but lack `openWorldHint: true`. The client has no signal that these tools reach beyond the server's primary backend.

**Required State:** Tools that interact with external systems beyond the server's backend MUST be annotated with `openWorldHint: true`. This gives the client and LLM accurate information about the tool's reach and enables clients to apply appropriate caution.

**Effort:** S
**Priority:** Medium

**Implementation Notes:**
- Identify all tools that interact with external systems. Known candidates: `ember_upload_media_file`, `ember_upload_scorm_package`, `ember_export_pdf`, `ember_export_scorm`, `ember_export_indesign`.
- Add `openWorldHint: true` to each of these tools' annotations.
- Review whether any other tools fetch from or post to URLs outside the Ember LMS API. If tools accept user-provided URLs (even indirectly via the GraphQL API), they are `openWorldHint: true` candidates.
- This gap is a subset of Gap 1 (Tool Annotations) but called out separately because `openWorldHint` has distinct security implications: it signals that the tool's blast radius extends beyond the controlled backend.

---

## Summary

| # | Gap | Spec Section | Effort | Priority | Status |
|---|-----|-------------|--------|----------|--------|
| 1 | Tool Annotations | 4.3 | S | Medium | Not Started |
| 2 | Rate Limiting | 4.6 | M | Critical | Not Started |
| 3 | Structured Logging | 9 | M | High | Not Started |
| 4 | Input Schema Tightening | 3.1, 3.3 | S | High | Not Started |
| 5 | Output Size Limits | 5.3 | S | Medium | Not Started |
| 6 | Tool Description Audit | 4.2 | S | High | Not Started |
| 7 | Dependency Vulnerability Scanning | 11.3 | S | High | Not Started |
| 8 | ATPA Defense | 5.4 | M | High | Not Started |
| 9 | Health Check | 13.4 | S | Medium | Not Started |
| 10 | openWorldHint on External Tools | 4.3 | S | Medium | Not Started |
