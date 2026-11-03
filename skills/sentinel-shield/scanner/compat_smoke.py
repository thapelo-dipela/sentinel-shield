#!/usr/bin/env python3
"""Opt-in live third-party scanner smoke test. ONLY in an isolated credential-free sandbox.

Requires independently trusted package digest and pinned scanner manifest; synthetic files
are data fixtures and NEVER imported or executed. No network isolation is enforced here.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def trusted_module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT/'scanner'/file)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    parser=argparse.ArgumentParser(description='Run pinned external scanner CLI compatibility smoke in an operator-enforced sandbox')
    parser.add_argument('--sandbox-confirmed',action='store_true',required=True)
    parser.add_argument('--tool-manifest',required=True)
    parser.add_argument('--expected-manifest-sha256',required=True)
    parser.add_argument('--timeout',type=int,default=120)
    args=parser.parse_args()
    if not args.sandbox_confirmed:
        parser.error('separate ephemeral sandbox, no credentials, and blocked egress are mandatory')
    verify=trusted_module('sentinel_compat_verify','verify_integrity.py')
    valid,reason=verify.verify(ROOT,args.expected_manifest_sha256)
    if not valid:
        print('Package integrity failed:',reason,file=sys.stderr)
        return 2
    sentinel=trusted_module('sentinel_compat_scanner','sentinel.py')
    manifest=Path(args.tool_manifest).resolve(strict=True)
    if manifest.is_relative_to(ROOT) or not manifest.is_file():
        parser.error('tool manifest must be outside skill package')
    entries=json.loads(manifest.read_text(encoding='utf-8'))
    with tempfile.TemporaryDirectory(prefix='sentinel-compat-fixtures-') as wd:
        target=Path(wd)/'repo';target.mkdir()
        (target/'tests').mkdir();(target/'vendor').mkdir()
        (target/'tests'/'shell.py').write_text('import subprocess\nsubprocess.run("echo synthetic", shell=True)\n')
        (target/'vendor'/'unsafe.js').write_text('eval(value);\n')
        # This hostile ignore must NEVER be honored by the trusted Semgrep shadow tree.
        (target/'.semgrepignore').write_text('*\n')
        results,states=sentinel.external(target,manifest,args.timeout)
    good=True
    for tool in ('semgrep','trivy','gitleaks'):
        status=states.get(tool,'not_configured')
        print(f'{tool}: {status}')
        if tool in entries and status!='ok':good=False
    if 'semgrep' in entries:
        targets={(x.rule_id,x.path) for x in results if x.source=='semgrep'}
        expected={'tests/shell.py','vendor/unsafe.js'}
        matches={path for _,path in targets}
        print('semgrep synthetic tested paths found:',len(matches & expected),'of',len(expected))
        if not expected.issubset(matches):good=False
    if not good:
        print('Compatibility smoke FAILED/INCOMPLETE. No live scan is certified.',file=sys.stderr)
        return 1
    print('Configured tools returned valid structured results for synthetic compatibility check only.')
    return 0

if __name__=='__main__':raise SystemExit(main())
