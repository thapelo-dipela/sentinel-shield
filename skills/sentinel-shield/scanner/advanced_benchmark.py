#!/usr/bin/env python3
"""Small maintainer-authored synthetic corpus. Not an independent measurement of accuracy."""
import argparse,json,tempfile,sys
from pathlib import Path
import importlib.util
SPEC = importlib.util.spec_from_file_location('trusted_sentinel_ast_engine', Path(__file__).resolve().with_name('advanced_engine.py'))
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
scan = MODULE.scan

def run(cases,js=True,typescript_file=None,typescript_sha256=None):
    details=[];tp=fp=fn=0;incomplete=0
    for case in cases:
        with tempfile.TemporaryDirectory(prefix='sentinel-bench-') as d:
            ext='.py' if case['language']=='python' else '.ts'
            (Path(d)/('test'+ext)).write_text(case['source'])
            report=scan(Path(d),js,typescript_file,typescript_sha256)
            pred={x['rule'] for x in report['findings']}
            expected=set(case['expected'])
            if report['status']=='completed':
                tp+=len(pred&expected);fp+=len(pred-expected);fn+=len(expected-pred)
            else:incomplete+=1
            details.append({'case_id':case['id'],'expected':sorted(expected),'predicted':sorted(pred),'gaps':report['gaps'],'status':report['status']})
    precision=tp/(tp+fp) if tp+fp else None
    recall=tp/(tp+fn) if tp+fn else None
    return {'kind':'maintainer-authored synthetic sanity benchmark','cases':len(cases),'complete_cases':len(cases)-incomplete,'incomplete_cases':incomplete,'tp':tp,'fp':fp,'fn':fn,'precision':precision,'recall':recall,'details':details,
            'warning':'Synthetic expected labels are maintainer defined; these numbers DO NOT estimate production accuracy or robust source-to-sink completeness.'}

def main():
    p=argparse.ArgumentParser();p.add_argument('--cases',required=True);p.add_argument('--output',required=True);p.add_argument('--typescript-file');p.add_argument('--typescript-sha256');a=p.parse_args()
    cases=json.loads(Path(a.cases).read_text());result=run(cases,typescript_file=a.typescript_file,typescript_sha256=a.typescript_sha256)
    out=Path(a.output)
    if out.exists() or out.is_symlink():raise ValueError('output exists')
    out.write_text(json.dumps(result,indent=2));print('synthetic cases:',result['cases'],'TP:',result['tp'],'FP:',result['fp'],'FN:',result['fn'])
if __name__=='__main__':main()
