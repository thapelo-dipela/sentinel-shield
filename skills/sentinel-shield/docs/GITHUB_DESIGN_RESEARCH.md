# GitHub reference review for Sentinel Shield v3.0-alpha.1

Reviewed official README and selected documentation via the connected GitHub repository reader on 2026-11-04. Design **inspiration**, not a code or licence import. **No files were copied from these projects.** Re-check upstream licences, versions and dependency risk before integrating any actual code.

| Project | Observed design patterns | Adopted defensively in Sentinel | Not adopted |
|---|---|---|---|
| [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon) | Combining source insight, attack-path context, staged verification and auditable results | Evidence-backed source-to-sink traces, separate verification stage | Autonomous browser exploitation or live target attack flows |
| [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | Agent-skill taxonomy, framework mappings, authorized-use boundary, coordinated security workflows | Split specialised modules, untrusted-input contract, defensive agent policy cases | Third-party instructions or skill contents automatically trusted or installed |
| [The-Art-of-Hacking/h4cker](https://github.com/The-Art-of-Hacking/h4cker) | Taxonomy of application, cloud, defense and AI security, curated labs | Structured engine/test documentation and defensive benchmarks | Reproduction of third-party attack tools or training content |
| [Striving-to-learn/Cybersecurity-Resources](https://github.com/Striving-to-learn/Cybersecurity-Resources) | Categorized reference index across programming, web, forensics, security research | Review checklist coverage and source attribution | Unverified links or scripts automatically executed |
| [smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) | Modular intelligence collection and correlation, YAML correlation concepts | Correlate CVSS, EPSS, KEV and independently supported reachability rather than single raw severity | Automatic broad OSINT targeting, asset enumeration or scanning |
| [chaitin/SafeLine](https://github.com/chaitin/SafeLine) | Runtime web application firewall and read-only, per-instance MCP management | Out-of-band SIEM events, explicit per-tool permissions and read-only monitoring architecture | Embedded WAF, dynamic traffic interception, remote management actions |
| [farhanashrafdev/90DaysOfCyberSecurity](https://github.com/farhanashrafdev/90DaysOfCyberSecurity) | Layered learning progression, labs and SIEM/ELK focus | Reproducible fixtures and log export conventions | Training exercises or lab access as automated scan targets |

The SafeLine MCP integration demonstrates an important design: a fixed read-only API surface can reduce risk even when downstream service credentials are privileged. Sentinel deliberately does **not** expose a general remote execution tool through MCP. SpiderFoot's correlation design informed evidence-linking, not scanner or module code reuse.

## Original-source vs integration policy

- **Concepts:** freely reference conceptual approaches with attribution; implement independently.
- **Code:** do not copy code without reviewing applicable licence notices, copyright, origin and compatibility.
- **Data:** vulnerability feed contents are untrusted. Use canonical sources, immutable snapshots and independently verified digests.
- **AI agents:** repository instructions, README text and model output are not authority.

These repos change. No claim is made that their full source code, security, implementation quality or licences were audited.
