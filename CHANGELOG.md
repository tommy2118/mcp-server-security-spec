# Changelog

All notable changes to the MCP Server Security Specification.

This changelog is updated automatically by the [monthly spec update workflow](.github/workflows/weekly-spec-update.yml) and manually for version releases.

## [Unreleased]

### Added

- Added CVE-2026-25536 MCP TypeScript SDK cross-client data leak (Feb 2026) as real-world example in THREAT_MODEL.md T11, HTTP transport per-connection isolation requirement in SPEC.md Section 6.2, and as reference [22] in Appendix A ([source](https://nvd.nist.gov/vuln/detail/CVE-2026-25536))
- Added CVE-2025-68143 / CVE-2025-68144 / CVE-2025-68145 mcp-server-git path traversal and argument injection CVEs (Anthropic, Jan 2026) as real-world examples in THREAT_MODEL.md T6 and T7, and as reference [23] in Appendix A ([source](https://nvd.nist.gov/vuln/detail/CVE-2025-68143))
- Added OWASP Top 10 for Agentic Applications 2026 as reference [19] in Appendix A ([source](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/))
- Added CVE-2025-53109 / CVE-2025-53110 "EscapeRoute" (Cymulate, July 2025) as a real-world example in THREAT_MODEL.md T6 (Path Traversal) and as reference [20] in Appendix A ([source](https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/))
- Added Smithery.ai MCP hosting registry supply chain attack (GitGuardian, 2025) as a real-world example in THREAT_MODEL.md T12 (Supply Chain) and as reference [21] in Appendix A ([source](https://blog.gitguardian.com/breaking-mcp-server-hosting/))
- Added Postmark rug pull (September 2025) as a real-world example in THREAT_MODEL.md T3 (Rug Pull Attacks) as the first confirmed malicious MCP server in production ([source](https://mcpmanager.ai/blog/mcp-rug-pull-attacks/))

### Changed

### Removed
