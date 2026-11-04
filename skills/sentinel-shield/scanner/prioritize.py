#!/usr/bin/env python3
"""Evidence-based CVE triage. Never invent CVSS, EPSS, KEV, or reachability signals.

Requires externally curated vulnerability report and separate intelligence snapshots.
Missing evidence is UNKNOWN, not clean or unreachable. No network operations.
"""
from __future__ import annotations
import argparse,hashlib,json,re,sys
from datetime import date
from pathlib import Path

CVE=re.compile(r'^CVE-\d{4}-\d{4,19}$')

def read(path,max_bytes=15_000_000):
    p=Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size>max_bytes:raise ValueError('unsafe or oversized input')
    return p.read_bytes()

def load(path):return json.loads(read(path))

def vulnerabilities(report):
    data=[]
    # Trivy modern result structure.
    for item in report.get('Results',[]):
        for vuln in item.get('Vulnerabilities') or []:
            cv=vuln.get('VulnerabilityID','').upper()
            if not CVE.fullmatch(cv):continue
            scores=vuln.get('CVSS') or {}
            base=[float(v[k]) for v in scores.values() if isinstance(v,dict) for k in ('V4Score','V3Score','V2Score') if isinstance(v.get(k),(int,float))]
            data.append({'cve':cv,'component':str(vuln.get('PkgName','unknown'))[:120],
                         'version':str(vuln.get('InstalledVersion',''))[:100],
                         'cvss':max(base) if base else None,'status':str(vuln.get('Status',''))[:40]})
    # CycloneDX inventory with vulnerability refs.
    for v in report.get('vulnerabilities',[]):
        cv=str(v.get('id','')).upper()
        if not CVE.fullmatch(cv):continue
        ratings=v.get('ratings') or []
        scores=[float(r['score']) for r in ratings if isinstance(r.get('score'),(int,float)) and 0<=float(r['score'])<=10]
        affected=v.get('affects') or [{}]
        for a in affected:
            data.append({'cve':cv,'component':str(a.get('ref','unknown'))[:120],
                         'version':'','cvss':max(scores) if scores else None,'status':'unknown'})
    return data

def verify_hash(blob, expected):
    if expected and hashlib.sha256(blob).hexdigest().lower()!=expected.lower():raise ValueError('trusted SHA256 does not match')

def kev_entries(document):
    if isinstance(document,dict):vals=document.get('vulnerabilities') or []
    else: vals=[]
    return {x.get('cveID','').upper() for x in vals if isinstance(x,dict) and CVE.fullmatch(str(x.get('cveID','')).upper())}

def epss_entries(doc):
    vals=doc.get('data') or []
    d={}
    for x in vals:
        try:
            v=float(x['epss']); c=str(x['cve']).upper()
            if CVE.fullmatch(c) and 0<=v<=1:d[c]={'epss':v,'percentile':float(x.get('percentile',0)),'date':str(x.get('date',''))}
        except (TypeError,ValueError,KeyError):continue
    return d

def classify(item,kev=None,epss=None,reachability='unknown',internet_exposed=None):
    score=item.get('cvss');prob=epss
    reasons=[]
    # "Confirmed" only when the caller supplied validated KEV catalog and verified hash.
    if kev is True:
        reasons.append('listed in supplied CISA KEV snapshot')
        if reachability=='reachable' and internet_exposed is True:return 'P0',reasons+['reachable internet-facing component']
        return 'P1',reasons
    if kev is None:reasons.append('KEV status unknown or not independently verified')
    if reachability=='reachable':reasons.append('supported reachable path')
    elif reachability=='reviewed_not_reachable':reasons.append('operator supplied negative-reachability evidence')
    else:reasons.append('reachability not established')
    if prob is None:reasons.append('EPSS unavailable')
    if score is None:reasons.append('CVSS unavailable')
    if reachability=='reachable' and ((score is not None and score>=9) or (prob is not None and prob>=.5)):
        return 'P1',reasons
    if reachability=='reachable' and ((score is not None and score>=7) or (prob is not None and prob>=.1)):
        return 'P2',reasons
    if reachability=='reviewed_not_reachable' and kev is False and (score or 0)<7 and (prob or 0)<.1:
        return 'P3',reasons
    return 'P2',reasons+['review required: missing or mixed evidence']

def prioritize(report, kev_document=None,kev_verified=False,epss_document=None,reachability_document=None):
    kev=kev_entries(kev_document) if kev_document else set()
    epss=epss_entries(epss_document) if epss_document else {}
    reach=reachability_document or {}
    rows=[]
    for v in vulnerabilities(report):
        cv=v['cve'];key=cv+'|'+v['component']
        entry=reach.get(key) or reach.get(cv) or {}
        state=entry.get('state','unknown')
        if state not in ('reachable','reviewed_not_reachable','unknown'):state='unknown'
        if state=='reviewed_not_reachable' and not entry.get('evidence'):state='unknown'
        ep=epss.get(cv,{}).get('epss')
        cvkev=(cv in kev) if kev_verified else None
        priority,reasons=classify(v,cvkev,ep,state,entry.get('internet_exposed'))
        rows.append({**v,'priority':priority,'kev':cvkev,'epss':ep,
                     'reachability':state,'reachability_evidence':bool(entry.get('evidence')),
                     'internet_exposed':entry.get('internet_exposed'),
                     'evidence':reasons})
    rows.sort(key=lambda x:({'P0':0,'P1':1,'P2':2,'P3':3}[x['priority']],x['cve'],x['component']))
    return {'version':'3.0.0-alpha.2','kind':'evidence-based-vulnerability-triage',
            'warning':'Priority is a local triage policy, not a CVSS or EPSS score. Missing evidence is unknown. No dependency reachability is inferred automatically.',
            'intel_status':{'kev_verified':kev_verified,'epss_available':bool(epss)},'items':rows}

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--vuln-report',required=True);p.add_argument('--kev-json');p.add_argument('--kev-sha256');p.add_argument('--epss-json');p.add_argument('--reachability-json');p.add_argument('--output',required=True)
    a=p.parse_args(argv)
    try:
        if a.kev_json and not a.kev_sha256:raise ValueError('independently trusted KEV digest required')
        kev=None
        if a.kev_json:
            blob=read(a.kev_json);verify_hash(blob,a.kev_sha256);kev=json.loads(blob)
            if len(kev_entries(kev))<1000:raise ValueError('KEV catalog unexpectedly short')
        doc=prioritize(load(a.vuln_report),kev,bool(kev),load(a.epss_json) if a.epss_json else None,load(a.reachability_json) if a.reachability_json else None)
        out=Path(a.output)
        if out.exists() or out.is_symlink():raise ValueError('output already exists')
        out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(doc,indent=2))
        print('triage completed: '+str(len(doc['items']))+' records; '+str(out))
        return 1 if any(x['priority']=='P0' for x in doc['items']) else 0
    except (ValueError,OSError,TypeError,KeyError,json.JSONDecodeError) as e:
        print('triage incomplete or unsafe input: '+type(e).__name__,file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
