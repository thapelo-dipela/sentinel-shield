"""Static tests of optional workflow templates. No workflow is executed."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]

class ReleaseTemplateTests(unittest.TestCase):
 def test_scheduled_workflow_scans_project_and_passes_real_cve_report(self):
  workflow=(ROOT/'templates/threat-intel-workflow.yml').read_text('utf-8')
  self.assertIn('trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz',workflow)
  self.assertIn('TRIVY_TARBALL_SHA256',workflow)
  self.assertIn('sha256sum --check',workflow)
  self.assertIn('--scanners vuln',workflow)
  self.assertIn('--vuln-report',workflow)
  self.assertIn('trivy-vulnerabilities.json',workflow)
  self.assertIn('if: always()',workflow)
  self.assertNotIn('pull_request:',workflow)
 def test_release_template_must_attest_real_zip_and_sbom(self):
  workflow=(ROOT/'templates/release-attestation-workflow.yml').read_text('utf-8')
  self.assertIn('SENTINEL_MANIFEST_SHA256',workflow)
  self.assertIn('git archive',workflow)
  self.assertIn('actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6',workflow)
  self.assertIn('subject-path: dist/Sentinel-Shield-verified.zip',workflow)
  self.assertIn('sbom-path:',workflow)
  self.assertIn('id-token: write',workflow)
 def test_trust_docs_do_not_claim_existing_signature(self):
  doc=(ROOT/'docs/RELEASE_SIGNING.md').read_text('utf-8')
  self.assertIn('no signed release',doc)
  self.assertIn('has **not** been executed',doc)

if __name__=='__main__':unittest.main()
