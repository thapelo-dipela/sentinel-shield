#!/usr/bin/env python3
"""Generate privacy-minimised JSONL security events for a trusted OTel/SIEM collector.
Never sends network requests. No raw source code, raw paths or credentials emitted.
"""
from __future__ import annotations
import argparse,datetime as dt,hashlib,json,sys
from pathlib import Path

SEV_NUM={'CRITICAL':21,'HIGH':17,'MEDIUM':13,'LOW':9,'INFO':5}

def sanitize(v,n=100):
    return ''.join(x for x in str(v)[:n] if x.isascii() and (x.isalnum() or x in ' _.:/-'))

def event(f,service,now):
    severity=sanitize(f.get('severity','INFO')).upper()
    return {'Timestamp':now,'SeverityText':severity,'SeverityNumber':SEV_NUM.get(severity,5),
        'EventName':'sentinel.security.finding',
        'Resource':{'service.name':sanitize(service),'service.version':'scanner-v3-alpha'},
        'Attributes':{'rule.id':sanitize(f.get('rule') or f.get('rule_id')),
            'source.name':sanitize(f.get('source','sentinel-engine')),
            'code.filepath.sha256':hashlib.sha256(str(f.get('file') or f.get('path','')).encode()).hexdigest(),
            'code.lineno':int(f.get('line',0)) if str(f.get('line','0')).isdigit() else 0,
            'security.finding.fingerprint':sanitize(f.get('fingerprint',''))},
        'Body':'Potential security vulnerability detected; consult secured finding report'}

def export(report,service='sentinel-app',now=None,format='otel'):
    ts=now or dt.datetime.now(dt.timezone.utc).isoformat()
    events=[event(f,service,ts) for f in report.get('findings',[])]
    if format=='otel': return events
    if format=='splunk':
        return [{'time':ts,'sourcetype':'sentinel:security','source':'sentinel-shield','event':e} for e in events]
    if format=='ecs':
        return [{'@timestamp':ts,'event':{'kind':'alert','category':['vulnerability'],'type':['info']},
                 'rule':{'id':e['Attributes']['rule.id']},
                 'log':{'level':e['SeverityText'].lower()},
                 'service':{'name':e['Resource']['service.name']},
                 'file':{'hash':{'sha256':e['Attributes']['code.filepath.sha256']}}} for e in events]
    raise ValueError('invalid export format')

def main():
    p=argparse.ArgumentParser();p.add_argument('--findings',required=True);p.add_argument('--service-name',required=True);p.add_argument('--output',required=True);p.add_argument('--format',choices=['otel','splunk','ecs'],default='otel')
    a=p.parse_args()
    try:
        src=Path(a.findings)
        if src.is_symlink() or src.stat().st_size>20_000_000:raise ValueError('unsafe report')
        result=export(json.loads(src.read_text()),a.service_name,format=a.format)
        target=Path(a.output)
        if target.exists() or target.is_symlink():raise ValueError('output exists')
        with target.open('x') as f:
            for item in result:f.write(json.dumps(item,ensure_ascii=True)+'\n')
        print('exported '+str(len(result))+' offline events to '+str(target))
        return 0
    except (ValueError,OSError,TypeError) as e:print('export refused: '+type(e).__name__,file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
