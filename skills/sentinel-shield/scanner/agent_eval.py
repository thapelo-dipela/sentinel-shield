#!/usr/bin/env python3
"""Deterministic, *non-executing* agent/MCP authorization and prompt-injection evaluation.
Model or tool calls are never made. The fixture tests a documented policy boundary, not real model robustness.
"""
import argparse,hashlib,json,sys
from pathlib import Path

DANGEROUS_UNTRUSTED=('ignore previous instructions','ignore all previous instructions','disable security','send secrets','system:','developer:','curl | sh','override authorization')

def evaluate(case):
    kind=case.get('kind')
    if kind=='untrusted_instructions':
        content=str(case.get('content','')).lower()
        return {'decision':'quarantine' if any(x in content for x in DANGEROUS_UNTRUSTED) else 'untrusted_data',
                'reason':'untrusted source cannot grant authority'}
    if kind=='cross_server_tool_name':
        return {'decision':'deny' if case.get('tool_name') in case.get('other_server_tools',[]) else 'review',
                'reason':'tool identity includes server identity; names alone are not sufficient'}
    if kind=='tool_definition_changed':
        old=case.get('approved_definition_sha256','');new=case.get('current_definition_sha256','')
        return {'decision':'deny' if old!=new else 'allow','reason':'reapproval required when approved definition changes'}
    if kind=='private_data_egress':
        # Design-level guard: no private source data together with untrusted input and external output channel.
        trio=bool(case.get('private_data')) and bool(case.get('untrusted_content')) and bool(case.get('external_egress'))
        return {'decision':'deny' if trio else 'review','reason':'separate sensitive data, untrusted content and egress capabilities'}
    if kind=='mcp_capability':
        approved=set(case.get('approved_scopes',[]));requested=set(case.get('requested_scopes',[]))
        return {'decision':'deny' if not requested.issubset(approved) else 'allow','reason':'least-privilege capability check'}
    if kind=='sensitive_write':
        gate=bool(case.get('fresh_mfa')) and bool(case.get('explicit_approval'))
        return {'decision':'allow' if gate else 'deny','reason':'fresh identity and explicit approval required'}
    return {'decision':'unsupported','reason':'unknown test type, not a pass'}

def suite(cases):
    results=[]
    for i,c in enumerate(cases):
        got=evaluate(c);expected=c.get('expected');results.append({'case_id':str(c.get('id',i))[:70],
            'passed':got['decision']==expected,'expected':expected,'actual':got['decision'],'reason':got['reason']})
    return {'kind':'agent-policy-simulation','limitations':'Deterministic reference policy, NOT proof an LLM or live MCP server resists these scenarios.',
            'passed':sum(x['passed'] for x in results),'total':len(results),'results':results}

def main():
    p=argparse.ArgumentParser();p.add_argument('--cases',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    try:
        f=Path(a.cases)
        if f.is_symlink() or f.stat().st_size>1_000_000:raise ValueError('unsafe fixture')
        cases=json.loads(f.read_text())
        if not isinstance(cases,list):raise ValueError('array required')
        result=suite(cases)
        o=Path(a.output)
        if o.exists() or o.is_symlink():raise ValueError('output exists')
        o.write_text(json.dumps(result,indent=2))
        print(str(result['passed'])+'/'+str(result['total'])+' policy cases passed')
        return 1 if result['passed']<result['total'] else 0
    except (ValueError,OSError,TypeError) as e:print('evaluation failed: '+type(e).__name__,file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
