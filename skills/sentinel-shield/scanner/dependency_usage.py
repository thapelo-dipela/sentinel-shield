#!/usr/bin/env python3
"""Non-executing package import hints for dependency triage.
Import != reachable vulnerable function. Not observed != unreachable.
"""
from __future__ import annotations
import argparse,ast,json,re,sys
from pathlib import Path
import importlib.util
SPEC = importlib.util.spec_from_file_location('trusted_sentinel_ast_engine', Path(__file__).resolve().with_name('advanced_engine.py'))
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
safe_walk = MODULE.safe_walk

RE_JS=re.compile(r'''\b(?:import\s+(?:[^;\n]{1,100}?\s+from\s+)?|require\s*\()\s*['"](@?[A-Za-z0-9_.\-/]+)['"]''')

def normalize(name):return str(name).replace('-','_').lower()

def inspect(root):
    seen={}
    for p in safe_walk(Path(root)):
        rel=p.relative_to(root).as_posix()
        try:code=p.read_text('utf8')
        except (UnicodeError,OSError):continue
        if p.suffix=='.py':
            try:tree=ast.parse(code)
            except SyntaxError:continue
            for node in ast.walk(tree):
                values=[]
                if isinstance(node,ast.Import):values=[a.name for a in node.names]
                if isinstance(node,ast.ImportFrom) and node.module:values=[node.module]
                for x in values:
                    key=normalize(x.split('.')[0]);seen.setdefault(key,set()).add(rel)
        else:
            for x in RE_JS.findall(code):
                key=x if x.startswith('@') and '/' in x else x.split('/')[0]
                seen.setdefault(normalize(key),set()).add(rel)
    return {k:sorted(v)[:15] for k,v in seen.items()}

def correlate(trivy_report,imports):
    hints=[]
    for group in trivy_report.get('Results',[]):
        for v in group.get('Vulnerabilities') or []:
            name=str(v.get('PkgName',''));key=normalize(name)
            paths=imports.get(key) or imports.get(key.split('/')[-1]) or []
            hints.append({'cve':v.get('VulnerabilityID'),'package':name,
                          'usage_hint':'import_observed' if paths else 'not_observed',
                          'source_file_count':len(paths),
                          'notice':'Import evidence only; requires call-graph and vulnerable function verification.'})
    return {'status':'review_required','limitations':'No lockfile resolution, version reachability, or vulnerable-function usage proof. A missing import is NOT evidence of unreachability.','packages':hints}

def main():
    p=argparse.ArgumentParser();p.add_argument('--path',required=True);p.add_argument('--vuln-report',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    try:
        root=Path(a.path).resolve(strict=True)
        report=json.loads(Path(a.vuln_report).read_text())
        out=Path(a.output)
        if out.exists() or out.is_symlink() or out.resolve().is_relative_to(root):raise ValueError('unsafe output')
        result=correlate(report,inspect(root));out.write_text(json.dumps(result,indent=2))
        print('package import hints: '+str(len(result['packages'])));return 0
    except (OSError,ValueError) as e:print('incomplete: '+type(e).__name__,file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
