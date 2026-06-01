# Changelog

All notable changes to the MCP Server Security Specification.

This changelog is updated automatically by the [monthly spec update workflow](.github/workflows/weekly-spec-update.yml) and manually for version releases.

## [Unreleased]

### Added

- Added SDK instance isolation requirement to SPEC.md Section 6.3: HTTP transport servers MUST NOT share a single McpServer instance across concurrent client connections; added corresponding checklist item ([source](https://nvd.nist.gov/vuln/detail/CVE-2026-25536))
- Added CVE-2026-25536 (TypeScript SDK cross-client data leak, CVSS 7.1, February 2026) as reference [23] in Appendix A ([source](https://nvd.nist.gov/vuln/detail/CVE-2026-25536))
- Added CVE-2025-68143 / CVE-2025-68144 / CVE-2025-68145 (mcp-server-git path traversal and argument injection, December 2025) as real-world examples in THREAT_MODEL.md T6 (Path Traversal) and T7 (Command Injection), and as reference [22] in Appendix A ([source](https://nvd.nist.gov/vuln/detail/CVE-2025-68143))
- Added CVE-2025-53967 (Framelink Figma MCP Server command injection, CVSS 8.0, October 2025) as a real-world example in THREAT_MODEL.md T7 (Command Injection) and as reference [24] in Appendix A ([source](https://nvd.nist.gov/vuln/detail/CVE-2025-53967))
- Added OX Security STDIO configuration injection disclosure (April 2026, 150M+ downloads affected) as a real-world example in THREAT_MODEL.md T12 (Supply Chain) and as reference [26] in Appendix A ([source](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/))
- Added arXiv:2510.16558 "A First Look at the Security Issues in the Model Context Protocol Ecosystem" (DSN 2026, analysis of 67,057 MCP servers) as reference [25] in Appendix A ([source](https://arxiv.org/abs/2510.16558))
- Added OWASP Top 10 for Agentic Applications 2026 as reference [19] in Appendix A ([source](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/))
- Added CVE-2025-53109 / CVE-2025-53110 "EscapeRoute" (Cymulate, July 2025) as a real-world example in THREAT_MODEL.md T6 (Path Traversal) and as reference [20] in Appendix A ([source](https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/))
- Added Smithery.ai MCP hosting registry supply chain attack (GitGuardian, 2025) as a real-world example in THREAT_MODEL.md T12 (Supply Chain) and as reference [21] in Appendix A ([source](https://blog.gitguardian.com/breaking-mcp-server-hosting/))
- Added Postmark rug pull (September 2025) as a real-world example in THREAT_MODEL.md T3 (Rug Pull Attacks) as the first confirmed malicious MCP server in production ([source](https://mcpmanager.ai/blog/mcp-rug-pull-attacks/))

### Changed

### Removed
