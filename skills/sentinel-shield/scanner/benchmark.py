#!/usr/bin/env python3
"""Offline synthetic scanner-signal benchmark. NEVER executes test-case code.

Do not interpret results as real-world SAST recall, precision, exploitability,
enterprise certification, or proof that a project is secure.
"""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]

def run_benchmark(corpus_path:Path=ROOT/'benchmarks'/'synthetic_corpus.json') -> dict:
    spec=importlib.util.spec_from_file_location('sentinel_benchmark_scanner',ROOT/'scanner'/'sentinel.py')
    scanner=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=scanner
    spec.loader.exec_module(scanner)
    data=json.loads(corpus_path.read_text('utf-8'))
    if not isinstance(data,dict) or not isinstance(data.get('cases'),list):raise ValueError('Invalid synthetic benchmark corpus')
    counters={'TP':0,'FP':0,'FN':0,'TN':0}; cases=[]
    with tempfile.TemporaryDirectory(prefix='sentinel-benchmark-') as temp:
        temp_root=Path(temp)
        for index,case in enumerate(data['cases']):
            # Strictly trusted fixture JSON from the integrity-verified skill, never an audited repository.
            if not isinstance(case,dict):raise ValueError('Invalid case')
            relative=Path(str(case['path']))
            if relative.is_absolute() or '..' in relative.parts:raise ValueError('Unsafe fixture relative path')
            if len(str(case.get('content',''))) > 20000:raise ValueError('Oversized case')
            target=temp_root/f'case_{index:03d}'
            target.mkdir()
            sample=target/relative
            sample.parent.mkdir(parents=True,exist_ok=True)
            sample.write_text(case['content'],'utf-8')
            findings,stats,configs=scanner.inspect(target,4000,512,64,4096)
            findings+=scanner.mcp(configs)
            actual={finding.rule_id for finding in findings}
            expected=case.get('expected_rule')
            if expected is not None:
                verdict='TP' if expected in actual else 'FN'
            else:
                # Negatives mean no HIGH/CRITICAL heuristic alerts in the fixture.
                verdict='FP' if any(finding.severity in {'CRITICAL','HIGH'} for finding in findings) else 'TN'
            counters[verdict]+=1
            cases.append({'id':case['id'],'expected_rule':expected,'observed_rules':sorted(actual),
                          'verdict':verdict,'coverage':'bounded local static scan'})
    tp,fp,fn=counters['TP'],counters['FP'],counters['FN']
    return {'benchmark':'synthetic-fixture-rule-signal-v1','scanner_version':scanner.VERSION,
            'cases_total':len(cases),'counts':counters,
            'precision':round(tp/(tp+fp),4) if tp+fp else None,
            'recall':round(tp/(tp+fn),4) if tp+fn else None,
            'limitations':'Synthetic fixtures chosen by skill maintainers; not validated exploitability, independent tests, or real-world generalization. Negative examples use high/critical signal threshold; not semantic vulnerability testing.',
            'cases':cases}

if __name__=='__main__':
    print(json.dumps(run_benchmark(),indent=2))
