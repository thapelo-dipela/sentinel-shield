#!/usr/bin/env python3
"""Compare proposed patched source tree to the original without executing either tree.
Safe static regression verification, not proof of functional correctness.
"""
import argparse,json,sys
from pathlib import Path
import importlib.util
SPEC = importlib.util.spec_from_file_location('trusted_sentinel_ast_engine', Path(__file__).resolve().with_name('advanced_engine.py'))
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
scan = MODULE.scan

def compare(before,after,js=False,typescript_file=None,typescript_sha256=None):
    a=scan(Path(before),js,typescript_file,typescript_sha256)
    b=scan(Path(after),js,typescript_file,typescript_sha256)
    af={x['fingerprint']:x for x in a['findings']};bf={x['fingerprint']:x for x in b['findings']}
    added=[{'rule':f['rule'],'file_id':f['fingerprint'],'severity':f['severity']} for k,f in bf.items() if k not in af]
    removed=[{'rule':f['rule'],'file_id':f['fingerprint'],'severity':f['severity']} for k,f in af.items() if k not in bf]
    return {'kind':'patch-static-regression','verified':not a['gaps'] and not b['gaps'],
            'status':'INCOMPLETE' if a['gaps'] or b['gaps'] else ('REGRESSION' if any(f['severity'] in ('HIGH','CRITICAL') for f in added) else 'NO_NEW_HIGH_CONFIRMED'),
            'new_leads':added,'removed_leads':removed,'before_count':len(af),'after_count':len(bf),
            'gaps_before':a['gaps'],'gaps_after':b['gaps'],
            'warning':'Static source-to-sink comparison only. NO repository tests executed. Existing source paths may remain exploitable despite fewer findings.'}

def main():
    p=argparse.ArgumentParser();p.add_argument('--before',required=True);p.add_argument('--after',required=True);p.add_argument('--js-ast',action='store_true');p.add_argument('--typescript-file');p.add_argument('--typescript-sha256');p.add_argument('--output',required=True)
    a=p.parse_args()
    try:
        report=compare(a.before,a.after,a.js_ast,a.typescript_file,a.typescript_sha256)
        out=Path(a.output)
        if out.exists() or out.is_symlink():raise ValueError('output already exists')
        out.write_text(json.dumps(report,indent=2))
        print(report['status']+' '+str(out))
        return 3 if report['status']=='INCOMPLETE' else (1 if report['status']=='REGRESSION' else 0)
    except (OSError,ValueError) as e:print('failed safely: '+type(e).__name__,file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
