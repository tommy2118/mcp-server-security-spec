# Changelog

All notable changes to the MCP Server Security Specification.

This changelog is updated automatically by the [monthly spec update workflow](.github/workflows/weekly-spec-update.yml) and manually for version releases.

## [Unreleased]

### Added

- Added MCP Specification Version 2026-07-28 as reference [23] in Appendix A, noting stateless protocol transition, RFC 9207 issuer validation requirement, HTTP+SSE transport deprecation (12-month deadline), and CIMD replacing DCR ([source](https://modelcontextprotocol.io/specification/2026-07-28/))
- Added RFC 9207 issuer validation requirement as Section 7.6.7, now mandated by MCP specification 2026-07-28 to close authorization-server mix-up attacks; added corresponding checklist item ([source](https://modelcontextprotocol.io/specification/2026-07-28/))
- Added HTTP+SSE transport deprecation notice in Section 6.2 with 12-month migration deadline per MCP specification 2026-07-28; noted removal of stateful `Mcp-Session-Id` handshake in new protocol version ([source](https://blog.modelcontextprotocol.io/posts/2026-07-28/))
- Added CIMD-replacing-DCR deprecation note in Section 7.6.4 per MCP specification 2026-07-28 ([source](https://modelcontextprotocol.io/specification/2026-07-28/))
- Added authentication adoption gap statistics in Section 7.1 from empirical measurement study (8.5% OAuth, 53% static API keys, 24-25% no auth, 492 zero-auth servers exposed to internet) ([source](https://arxiv.org/pdf/2605.22333))
- Added NSA Artificial Intelligence Security Center Cybersecurity Information Sheet on MCP security (June 2, 2026) as reference [24] in Appendix A ([source](https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF))
- Added CVE-2026-33032 ("MCPwn", CVSS 9.8, actively exploited) as reference [25] in Appendix A; added as real-world example in THREAT_MODEL.md T11 (Session Hijacking) and noted in threat catalog T11 row ([source](https://www.picussecurity.com/resource/blog/cve-2026-33032-mcpwn-how-a-missing-middleware-call-in-nginx-ui-hands-attackers-full-web-server-takeover))
- Added arXiv:2605.22333 authentication measurement study as reference [26] in Appendix A ([source](https://arxiv.org/pdf/2605.22333))
- Updated THREAT_MODEL.md T11 description to add missing-authentication-middleware as a fourth hijacking vector and to note MCP specification 2026-07-28 stateless protocol transition ([source](https://modelcontextprotocol.io/specification/2026-07-28/))
- Added mitigation row for authentication middleware coverage to THREAT_MODEL.md T11 mitigations table ([source](https://www.picussecurity.com/resource/blog/cve-2026-33032-mcpwn-how-a-missing-middleware-call-in-nginx-ui-hands-attackers-full-web-server-takeover))
- Added CoSAI / OASIS Workstream 4 MCP Security Taxonomy (approved January 8, 2026) as reference [22] in Appendix A, and added Asana tenant isolation and WordPress MCP privilege escalation incidents as real-world examples in THREAT_MODEL.md T10 (Confused Deputy) ([source](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md))
- Added OWASP Top 10 for Agentic Applications 2026 as reference [19] in Appendix A ([source](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/))
- Added CVE-2025-53109 / CVE-2025-53110 "EscapeRoute" (Cymulate, July 2025) as a real-world example in THREAT_MODEL.md T6 (Path Traversal) and as reference [20] in Appendix A ([source](https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/))
- Added Smithery.ai MCP hosting registry supply chain attack (GitGuardian, 2025) as a real-world example in THREAT_MODEL.md T12 (Supply Chain) and as reference [21] in Appendix A ([source](https://blog.gitguardian.com/breaking-mcp-server-hosting/))
- Added Postmark rug pull (September 2025) as a real-world example in THREAT_MODEL.md T3 (Rug Pull Attacks) as the first confirmed malicious MCP server in production ([source](https://mcpmanager.ai/blog/mcp-rug-pull-attacks/))

### Changed

### Removed
