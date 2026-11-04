# Independent real-world benchmark protocol (not executed)

The shipped synthetic corpus demonstrates deterministic rule signals only. It is **not** a measurement of real-world recall, precision, false negatives, exploitability, or enterprise readiness.

## Proposed independent evaluation

- Acquire reviewed, **pinned and hash-verified** releases of OWASP Juice Shop and OWASP NodeGoat, or equivalent expressly licensed training apps, through approved channels. Do not run public targets or use real personal data. Do not execute malicious repo scripts on developer machines.
- Keep all test applications inside temporary, no-credential, egress-restricted sandboxes. Run the read-only Sentinel source scan before any test app execution. Any dynamic activity requires additional approval and isolation.
- Use a separately curated issue manifest identifying confirmed vulnerability categories and source paths. Do not author the labels from the scanner output or choose the fixture set solely because existing rules match.
- Score detections by category and by reviewed vulnerability identity, not by arbitrary substring overlap. Human-review ambiguous matches and document exact true-positive, false-positive and false-negative criteria.
- Publish tool versions and digests, pinned app commit SHAs, corpus hashes, hardware/resource limits, elapsed run time, scan scope and excluded files. Report false-positive rate, recall and precision with raw counts and confidence intervals where appropriate.
- Compare changes across v2.4, v2.5 and relevant industry scanners with the same corpus and resource limits. Include Supabase RLS/MCP fixtures and malicious repo instruction cases, but keep active exploitation outside the automated skill workflow.

No such independent benchmark is included. `python3 -B -I scanner/benchmark.py` remains the reproducible synthetic-only run and is not an enterprise capability claim.
