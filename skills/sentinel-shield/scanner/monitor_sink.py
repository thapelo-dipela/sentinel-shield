#!/usr/bin/env python3
"""Explicit opt-in HTTPS SIEM push for *sanitized* Sentinel events only.
Never use automatically. Does not watch production, intercept traffic or read credentials from repo.
"""
import argparse,json,os,sys,urllib.parse,urllib.request
from pathlib import Path

def validate_destination(url,approved_host):
    p=urllib.parse.urlsplit(url)
    if p.scheme!='https' or p.hostname!=approved_host or p.username or p.password or p.fragment or p.query:
        raise ValueError('HTTPS destination must match exact approved host; credentials/queries forbidden')
    if not p.path.startswith('/') or '//' in p.path:raise ValueError('invalid destination path')
    return url

class DenyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('redirect refused')

def send(events,url,approved_host,token,allow_network=False,mode='splunk'):
    validate_destination(url,approved_host)
    if not allow_network:raise ValueError('explicit --allow-network required')
    if not token:raise ValueError('missing authenticated token')
    if mode not in ('splunk','jsonl'):raise ValueError('unsupported mode')
    if not isinstance(events,list) or len(events)>1000:raise ValueError('too many events')
    required={'Timestamp','SeverityText','SeverityNumber','EventName','Resource','Attributes','Body'}
    permitted_attrs={'rule.id','source.name','code.filepath.sha256','code.lineno','security.finding.fingerprint'}
    for x in events:
        if not isinstance(x,dict) or set(x)!=required or x.get('EventName')!='sentinel.security.finding':
            raise ValueError('only canonical Sentinel security events accepted')
        attrs=x.get('Attributes')
        if not isinstance(attrs,dict) or not set(attrs).issubset(permitted_attrs):
            raise ValueError('unapproved attributes in security event')
        if str(x.get('Body'))!='Potential security vulnerability detected; consult secured finding report':
            raise ValueError('unsafe event body')
    # Always derive Splunk body from sanitized event data with explicit JSON content type.
    body=''.join(json.dumps({'event':e,'sourcetype':'sentinel:security'} if mode=='splunk' else e,ensure_ascii=True)+'\n' for e in events).encode()
    if len(body)>1_000_000:raise ValueError('large export refused')
    auth=('Splunk ' if mode=='splunk' else 'Bearer ')+token
    req=urllib.request.Request(url,data=body,headers={'Authorization':auth,'Content-Type':'application/json'},method='POST')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),DenyRedirect())
    with opener.open(req,timeout=10) as resp:
        if resp.status<200 or resp.status>=300:raise ValueError('SIEM did not confirm delivery')
    return {'sent':len(events),'destination_host':approved_host,'status':'submitted'}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--events',required=True);p.add_argument('--url',required=True);p.add_argument('--approved-host',required=True)
    p.add_argument('--allow-network',action='store_true');p.add_argument('--mode',choices=['splunk','jsonl'],default='splunk')
    p.add_argument('--token-env',default='SENTINEL_SIEM_TOKEN')
    a=p.parse_args()
    try:
        source=Path(a.events)
        if source.is_symlink() or source.stat().st_size>1_000_000:raise ValueError('unsafe event input')
        events=[json.loads(line) for line in source.read_text().splitlines() if line.strip()]
        result=send(events,a.url,a.approved_host,os.environ.get(a.token_env),a.allow_network,a.mode)
        print(json.dumps(result));return 0
    except (OSError,ValueError,TypeError,urllib.error.URLError) as e:
        print('monitor sink incomplete: '+type(e).__name__,file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
