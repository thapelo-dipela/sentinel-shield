#!/usr/bin/env python3
"""Sentinel Shield threat intelligence: explicit network refresh, offline review.

Sources: official CISA KEV + advisory RSS; OWASP VWAD curated lab directory.
Never runs repository code, opens linked advisories, or tests vulnerable targets.
No remote text is interpreted as commands. No network access in review mode.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
import stat
from pathlib import Path
import re
import sys
import tempfile
from urllib import request, error, parse
import xml.etree.ElementTree as ET

VERSION='2.5.0'
CISA_KEV='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
CISA_MIRROR_API='https://api.github.com/repos/cisagov/kev-data/commits/develop'
CISA_MIRROR_PREFIX='https://raw.githubusercontent.com/cisagov/kev-data/'
CISA_MIRROR_SUFFIX='/known_exploited_vulnerabilities.json'
MIRROR_SHA_RE=re.compile(r'^[a-f0-9]{40}$')
MIN_KEV_ENTRIES=1000
MAX_KEV_DROP_FRACTION=0.15
CISA_ADVISORIES='https://www.cisa.gov/cybersecurity-advisories/all.xml'
VWAD_CATALOG='https://raw.githubusercontent.com/owasp-vwad/owasp-vwad.github.io/main/data/collection.json'
FETCH_SOURCES={'kev':(CISA_KEV,CISA_MIRROR_API),'advisories':(CISA_ADVISORIES,),'vwad':(VWAD_CATALOG,)}
LIMITS={'kev':12_000_000,'advisories':4_000_000,'vwad':8_000_000}
CVE_RE=re.compile(r'^CVE-\d{4}-\d{4,}$',re.I)
CVE_SEARCH=re.compile(r'\bCVE-\d{4}-\d{4,}\b',re.I)
SAFE_TEXT_RE=re.compile(r'[^\w ,.:;()\-/+@#]')
MAX_ENTRIES={'kev':10000,'advisories':500,'vwad':3000}


def clean(v,limit=220):
    # Source strings are untrusted even when downloaded from reputable publishers.
    s=' '.join(str(v)[:limit*2].split())
    if re.search(r'(ignore (all )?(previous|prior) instructions|disable (the )?(audit|security|scanner)|\b(system|assistant|developer)\s*:)',s,re.I):
        return 'untrusted-feed-text-'+hashlib.sha256(s.encode('utf-8','replace')).hexdigest()[:12]
    return SAFE_TEXT_RE.sub('_',s)[:limit]


def iso_now():return datetime.now(timezone.utc).isoformat(timespec='seconds')


def date_ymd(value):
    v=str(value or '')
    try:return datetime.strptime(v[:10],'%Y-%m-%d').date().isoformat()
    except ValueError:return ''


def json_bounded(raw):
    return json.loads(raw.decode('utf-8'))


def parse_kev(raw):
    obj=json_bounded(raw)
    if not isinstance(obj,dict) or not isinstance(obj.get('vulnerabilities'),list):raise ValueError('Invalid CISA KEV JSON schema')
    items=obj['vulnerabilities']
    if not 0<len(items)<=MAX_ENTRIES['kev']:raise ValueError('CISA KEV unexpected entry count')
    unique={}
    for row in items:
        if not isinstance(row,dict):continue
        cve=str(row.get('cveID','')).upper()
        if not CVE_RE.fullmatch(cve):continue
        unique[cve]={'cve':cve,'vendor':clean(row.get('vendorProject','')),
           'product':clean(row.get('product','')),'name':clean(row.get('vulnerabilityName','')),
           'date_added':date_ymd(row.get('dateAdded')),'due_date':date_ymd(row.get('dueDate')),
           'ransomware':clean(row.get('knownRansomwareCampaignUse','Unknown'),40),
           'cwes':[str(x) for x in row.get('cwes',[])[:10] if isinstance(x,str) and re.fullmatch(r'CWE-\d+',x)]}
    if not unique:raise ValueError('CISA KEV no valid CVEs')
    return {'catalog_version':clean(obj.get('catalogVersion',''),48),'date_released':clean(obj.get('dateReleased',''),48),
            'items':[unique[k] for k in sorted(unique)]}


def parse_advisories(raw):
    # Parse only UTF-8: UTF-16 and other encodings could evade byte-level DTD screening.
    if b'\x00' in raw:raise ValueError('Non-UTF-8 XML encoding refused')
    try:xml=raw.decode('utf-8-sig')
    except UnicodeError as exc:raise ValueError('Non-UTF-8 XML encoding refused') from exc
    prolog=re.match(r'\s*<\?xml\s+[^>]{0,250}\?>',xml,re.I)
    if prolog:
        enc=re.search(r'encoding\s*=\s*[\"\']([^\"\']+)[\"\']',prolog.group(),re.I)
        if enc and enc.group(1).lower() not in ('utf-8','utf8'):raise ValueError('Only UTF-8 RSS allowed')
    if '<!DOCTYPE' in xml.upper() or '<!ENTITY' in xml.upper():raise ValueError('XML DTD/entities refused')
    try:root=ET.fromstring(xml)
    except ET.ParseError as exc:raise ValueError('Invalid CISA RSS XML') from exc
    if root.tag.lower()!='rss':raise ValueError('Expected CISA RSS root')
    entries=[];seen=set()
    for e in root.findall('./channel/item')[:MAX_ENTRIES['advisories']]:
        title=clean(e.findtext('title',''))
        link=(e.findtext('link','') or '').strip()
        url=parse.urlparse(link)
        # Link is optional, but must be hosted on CISA to keep it as a reference.
        safe_url=link if url.scheme=='https' and (url.hostname=='cisa.gov' or (url.hostname or '').endswith('.cisa.gov')) else ''
        key=hashlib.sha256((title+'|'+safe_url).encode()).hexdigest()[:20]
        if not title or key in seen:continue
        seen.add(key)
        when=''
        published=(e.findtext('pubDate') or '').strip()
        try:when=parsedate_to_datetime(published).astimezone(timezone.utc).date().isoformat()
        except (TypeError, ValueError,OverflowError):pass
        # No full descriptions or HTML are retained in any output.
        desc=e.findtext('description','') or ''
        refs=sorted(set(x.upper() for x in CVE_SEARCH.findall(title+' '+desc)))[:20]
        entries.append({'id':key,'title':title,'published':when,'url':safe_url,'cves':refs})
    if not entries:raise ValueError('CISA advisory feed contains no items')
    return {'items':entries}


def parse_vwad(raw):
    obj=json_bounded(raw)
    if not isinstance(obj,list) or not 0<len(obj)<=MAX_ENTRIES['vwad']:raise ValueError('OWASP VWAD invalid collection')
    entries=[];seen=set()
    for e in obj:
        if not isinstance(e,dict):continue
        slug=str(e.get('slug','')).strip().lower()
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,99}',slug) or slug in seen:continue
        seen.add(slug)
        entries.append({'slug':slug,'name':clean(e.get('name',''),100),
          'technologies':[clean(x,45) for x in e.get('technology',[])[:25] if isinstance(x,str)],
          'collections':[clean(x,24) for x in e.get('collection',[])[:10] if isinstance(x,str)],
          'categories':[clean(x,32) for x in e.get('categories',[])[:15] if isinstance(x,str)],
          'directory_url':f'https://vwad.owasp.org/app/{slug}/'})
    if not entries:raise ValueError('OWASP VWAD no validated entries')
    return {'items':entries}


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,hdrs,newurl):
        raise ValueError('Feed redirect refused: source URL must be reviewed before allowlisting')


def fetch_exact(url,byte_limit,opener=None):
    pinned=(url.startswith(CISA_MIRROR_PREFIX) and url.endswith(CISA_MIRROR_SUFFIX)
            and MIRROR_SHA_RE.fullmatch(url[len(CISA_MIRROR_PREFIX):-len(CISA_MIRROR_SUFFIX)]) is not None)
    if not pinned and url not in {v for endpoints in FETCH_SOURCES.values() for v in endpoints}:
        raise ValueError('Unapproved feed URL')
    client=opener or request.build_opener(NoRedirect)
    req=request.Request(url,headers={'User-Agent':'SentinelShield-ThreatIntel/2.5 (defensive; read-only)',
                                    'Accept':'application/json, application/rss+xml, application/xml'})
    with client.open(req,timeout=15) as res:
        status=getattr(res,'status',200)
        if status!=200:raise ValueError('Feed HTTP status not 200')
        raw=res.read(byte_limit+1)
    if len(raw)>byte_limit:raise ValueError('Feed size exceeds fixed limit')
    if not raw:raise ValueError('Empty feed')
    return raw


def trusted_cache_path(cache_dir,repo_root=None):
    """Refuse symlinked components, repo-local caches and shared/unowned cache storage.

    This protects against other local users; it is NOT a signature or defense against
    an attacker running with the same OS user account. Cache freshness alone is never
    proof of publisher authenticity.
    """
    supplied=Path(cache_dir).expanduser()
    if '..' in supplied.parts:raise ValueError('Parent traversal in cache path refused')
    p=Path(os.path.abspath(supplied))  # NOT resolve(): resolving erases symlink evidence.
    # Default to working directory, or discover its containing git repo if present.
    project=Path(repo_root).expanduser().resolve() if repo_root is not None else Path.cwd().resolve()
    if repo_root is None:
        for candidate in (project,*project.parents):
            if (candidate/'.git').exists():project=candidate;break
    if p==project or p.is_relative_to(project):raise ValueError('Cache must be outside audited repository')
    segment=Path(p.anchor)
    for part in p.parts[1:]:
        segment=segment/part
        if segment.is_symlink():raise ValueError('Cache path contains symlink')
    p.mkdir(parents=True,exist_ok=True,mode=0o700)
    if not p.is_dir():raise ValueError('Not a cache directory')
    if os.name=='posix':
        st=p.stat()
        if st.st_uid!=os.getuid() or (st.st_mode & (stat.S_IRWXG|stat.S_IRWXO)):
            raise ValueError('Cache directory must be owned by current user and mode 0700')
    return p


def secure_read_cache(cache:Path,name:str) -> bytes:
    path=cache/name
    if path.is_symlink():raise ValueError('Cache file symlink refused')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1:
            raise ValueError('Cache file must be a single regular file')
        if os.name=='posix' and (meta.st_uid!=os.getuid() or meta.st_mode & (stat.S_IRWXG|stat.S_IRWXO)):
            raise ValueError('Cache files must be owner-only')
        if meta.st_size>LIMITS[name.split('.')[0]]*2+2_000_000:raise ValueError('Cache exceeds maximum size')
        with os.fdopen(fd,'rb') as f:
            fd=-1
            return f.read(LIMITS[name.split('.')[0]]*2+2_000_001)
    finally:
        if fd>=0:os.close(fd)


def write_atomic(parent,name,payload):
    path=parent/name
    if path.is_symlink():raise ValueError('Cache file symlink refused')
    fd,temp=tempfile.mkstemp(prefix='.threat-intel-',dir=parent)
    try:
        if hasattr(os,'fchmod'):os.fchmod(fd,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as fh:
            json.dump(payload,fh,sort_keys=True,indent=2)
            fh.write('\n')
            fh.flush();os.fsync(fh.fileno())
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):os.unlink(temp)


def pinned_mirror_url(fetch):
    """Resolve mutable mirror HEAD into an immutable commit URL before fetching data."""
    body=json.loads(fetch(CISA_MIRROR_API,100_000).decode('utf-8'))
    sha=body.get('sha') if isinstance(body,dict) else None
    if not isinstance(sha,str) or not MIRROR_SHA_RE.fullmatch(sha):
        raise ValueError('GitHub KEV mirror commit API did not return 40-char SHA')
    return CISA_MIRROR_PREFIX+sha+CISA_MIRROR_SUFFIX,sha


def validate_snapshot(cache,name):
    """Fail closed unless raw source digest and canonical parsed rows match.

    The feed is TLS-fetched but not signed. A same-user attacker who can rewrite both
    the cache file and its raw data can still forge a self-consistent snapshot.
    """
    blob=secure_read_cache(cache,name+'.json')
    d=json.loads(blob.decode('utf-8'))
    if not isinstance(d,dict) or d.get('schema')!='sentinel-threat-intel-v2' or d.get('source')!=name:
        raise ValueError('Cache schema version requires trusted refresh')
    allowed=set(FETCH_SOURCES[name])
    url=d.get('source_url')
    pinned=(isinstance(url,str) and url.startswith(CISA_MIRROR_PREFIX) and url.endswith(CISA_MIRROR_SUFFIX)
            and MIRROR_SHA_RE.fullmatch(url[len(CISA_MIRROR_PREFIX):-len(CISA_MIRROR_SUFFIX)]) is not None)
    if url not in allowed and not (name=='kev' and pinned):raise ValueError('Unapproved cached source URL')
    encoded=d.get('raw_feed_b64')
    if not isinstance(encoded,str):raise ValueError('Raw feed missing from cache')
    raw=base64.b64decode(encoded,validate=True)
    if not raw or len(raw)>LIMITS[name]:raise ValueError('Raw feed size invalid')
    if hashlib.sha256(raw).hexdigest()!=d.get('source_sha256'):raise ValueError('Raw feed SHA256 mismatch')
    payload={'kev':parse_kev,'advisories':parse_advisories,'vwad':parse_vwad}[name](raw)
    if name=='kev' and len(payload['items'])<MIN_KEV_ENTRIES:
        raise ValueError('KEV count below security minimum')
    if d.get('items')!=payload['items'] or d.get('total')!=len(payload['items']):
        raise ValueError('Cached parsed feed diverges from raw feed')
    if not isinstance(d.get('new_count'),int) or not 0<=d['new_count']<=d['total']:
        raise ValueError('Bad cache metadata')
    timestamp=datetime.fromisoformat(d.get('fetched_utc',''))
    if timestamp.tzinfo is None:raise ValueError('Missing timezone')
    max_age=timedelta(days=30 if name=='vwad' else 3)
    age=datetime.now(timezone.utc)-timestamp
    status='stale' if age>max_age or age<timedelta(days=-1) else 'current'
    return d,status


def refresh(cache_dir,fetch=fetch_exact,repo_root=None):
    cache=trusted_cache_path(cache_dir,repo_root)
    results={};errors={}
    for name,urls in FETCH_SOURCES.items():
        failures=[]
        for url in urls:
            try:
                mirror_commit=None
                source_url=url
                if name=='kev' and url==CISA_MIRROR_API:
                    source_url,mirror_commit=pinned_mirror_url(fetch)
                raw=fetch(source_url,LIMITS[name])
                payload=({'kev':parse_kev,'advisories':parse_advisories,'vwad':parse_vwad}[name])(raw)
                if name=='kev' and len(payload['items'])<MIN_KEV_ENTRIES:
                    raise ValueError('KEV source below trusted minimum catalog size')
                old,status=load_snapshot(cache,name)
                if old and name=='kev' and len(payload['items']) < len(old['items'])*(1-MAX_KEV_DROP_FRACTION):
                    raise ValueError('KEV catalog sudden count drop; retaining previous snapshot')
                key='cve' if name=='kev' else 'id' if name=='advisories' else 'slug'
                prior={r[key] for r in old.get('items',[]) if isinstance(r,dict) and key in r} if old else set()
                current={r[key] for r in payload['items']}
                record={'schema':'sentinel-threat-intel-v2','source':name,'source_url':source_url,
                        'fetched_utc':iso_now(),'source_sha256':hashlib.sha256(raw).hexdigest(),
                        'raw_feed_b64':base64.b64encode(raw).decode('ascii'),
                        'items':payload['items'],'new_ids':sorted(current-prior)[:MAX_ENTRIES[name]],
                        'new_count':len(current-prior),'total':len(payload['items'])}
                if mirror_commit:record['mirror_commit_sha']=mirror_commit
                for k in ('catalog_version','date_released'):
                    if k in payload:record[k]=payload[k]
                write_atomic(cache,name+'.json',record)
                results[name]={'status':'updated','total':record['total'],'new_count':record['new_count'],
                               'fetched_utc':record['fetched_utc'],'source_url':source_url,
                               'source_sha256':record['source_sha256']}
                break
            except (OSError,ValueError,error.URLError,UnicodeError,TypeError) as exc:
                failures.append(type(exc).__name__)
        if name not in results:
            errors[name]='failed_to_refresh:'+','.join(failures)
            results[name]={'status':'stale_or_missing','error':errors[name]}
    return {'version':VERSION,'results':results,'incomplete':bool(errors)}


def load_snapshot(cache,name):
    try:
        return validate_snapshot(cache,name)
    except (OSError,ValueError,TypeError,KeyError,UnicodeError):
        return None,'invalid_or_missing'


def collect_cves(obj):
    """CVE IDs from structured vulnerability reports only; never guesses package versions."""
    found=set()
    def add(value):
        if isinstance(value,str) and CVE_RE.fullmatch(value.upper()):found.add(value.upper())
    if not isinstance(obj,dict):raise ValueError('Vulnerability report must be JSON object')
    # CycloneDX 1.5/1.6 vulnerability entries.
    for row in obj.get('vulnerabilities',[])[:30000]:
        if isinstance(row,dict):add(row.get('id'))
    # Trivy JSON results.
    for result in obj.get('Results',[])[:5000]:
        if not isinstance(result,dict):continue
        for row in (result.get('Vulnerabilities') or [])[:30000]:
            if isinstance(row,dict):add(row.get('VulnerabilityID'))
    # Sentinel scan metadata may contain CVEs only as structured fields; do NOT grep arbitrary text.
    for row in obj.get('findings',[])[:30000]:
        if isinstance(row,dict):add(row.get('cve'))
    return found


def review(cache_dir,report_path=None,technologies=(),max_items=20,inventory_path=None,repo_root=None):
    cache=trusted_cache_path(cache_dir,repo_root)
    snapshots={};statuses={}
    for name in FETCH_SOURCES:
        snapshots[name],statuses[name]=load_snapshot(cache,name)
    seen=set()
    if report_path:
        p=Path(report_path).expanduser().resolve(strict=True)
        if p.stat().st_size>16_000_000:raise ValueError('Vulnerability report exceeds fixed size limit')
        seen=collect_cves(json.loads(p.read_text('utf-8')))
    exact=[];bycve={}
    if snapshots['kev']:
        bycve={row['cve']:row for row in snapshots['kev']['items'] if isinstance(row,dict) and CVE_RE.fullmatch(str(row.get('cve','')))}
        exact=[{'cve':cve,'vendor':bycve[cve]['vendor'],'product':bycve[cve]['product'],
               'date_added':bycve[cve]['date_added'],'cisa_due_date':bycve[cve].get('due_date',''),
               'match_type':'exact_cve_in_supplied_vulnerability_report',
               'action':'Investigate applicability and apply vendor remediation; determine exposure and reachability.'}
               for cve in sorted(seen & bycve.keys())][:max_items]
    inventory=[]
    if inventory_path:
        p=Path(inventory_path).expanduser().resolve(strict=True)
        if p.stat().st_size>1_000_000:raise ValueError('Inventory exceeds fixed size limit')
        obj=json.loads(p.read_text('utf-8'))
        if not isinstance(obj,list) or len(obj)>1000:raise ValueError('Asset inventory must be an array with <=1000 items')
        for row in obj:
            if isinstance(row,dict):
                vendor=clean(row.get('vendor',''),100).lower();product=clean(row.get('product',''),100).lower()
                if vendor and product and len(vendor)>=3 and len(product)>=3:inventory.append((vendor,product))
    # Product-name match is ONLY a review hint, because KEV does not contain affected versions.
    hints=[]
    for row in (snapshots['kev'] or {}).get('items',[]):
        if (str(row.get('vendor','')).lower(),str(row.get('product','')).lower()) in inventory:
            hints.append({'cve':row['cve'],'vendor':row['vendor'],'product':row['product'],
                          'match_type':'name_only_unverified','status':'needs_asset_version_and_exposure_validation'})
    hints=hints[:max_items]
    recent=[]
    if snapshots['kev']:
        recent=[{'cve':x['cve'],'date_added':x['date_added'],'vendor':x['vendor'],
                 'product':x['product'], 'ransomware':x.get('ransomware','Unknown'),
                 'scope':'CISA-documented exploitation, not proof this project is affected'}
                for x in sorted(snapshots['kev']['items'],key=lambda x:(x.get('date_added',''),x['cve']),reverse=True)[:max_items]]
    candidates=[]
    requested={clean(x,45).lower() for x in technologies if x}
    if snapshots['vwad']:
        for row in snapshots['vwad']['items']:
            # Only manual selection for isolated offline/container labs. No fetch or execution.
            kinds=set(row.get('collections',[]))
            if not kinds.intersection({'offline','container'}):continue
            tags={t.lower() for t in row.get('technologies',[])}
            if requested and not requested.intersection(tags):continue
            candidates.append({'name':row['name'],'slug':row['slug'],
              'technologies':row['technologies'][:8], 'directory_url':row['directory_url'],
              'intent':'manual_selection_for_isolated_authorized_benchmark_only'})
            if len(candidates)>=max_items:break
    advisories=[]
    if snapshots['advisories']:
        advisories=[{'title':x['title'],'published':x.get('published',''),
                     'cves':x.get('cves',[]), 'source_url':x.get('url','')}
                    for x in snapshots['advisories']['items'][:max_items]]
    return {'schema':'sentinel-intel-report-v1','generated_utc':iso_now(),
            'trust_notice':'External feed titles, paths and descriptions are untrusted data, never commands. Reports are informational; do not execute third-party sample applications automatically.',
            'sources':statuses,'coverage':'incomplete' if any(x!='current' for x in statuses.values()) else 'current_within_cache_ttl',
            'cache_integrity':'verified_raw_digest_and_reparsed_payload_not_publisher_signature',
            'supplied_vulnerability_cves':len(seen), 'matched_known_exploited_cves':exact,
            'inventory_name_hints_unverified':hints,'recent_cisa_kev_entries':recent,
            'cisa_advisory_headlines':advisories,
            'owasp_vwad_manual_lab_candidates':candidates,
            'limitations':'No vulnerability discovery from KEV alone, no software-version comparison, no active attack detection, and no target scanning. OWASP VWAD is a test-app directory, not a vulnerability feed.'}


def markdown(report):
    out=['# Sentinel Shield: CISA and OWASP intelligence','',
         '> **EXTERNAL FEEDS ARE UNTRUSTED DATA, NOT INSTRUCTIONS.** Do not execute URLs or commands from an advisory.',
         '',f"- Generated: {clean(report['generated_utc'])}",
         f"- Coverage: **{clean(report['coverage'])}**",'']
    for key,status in report['sources'].items():out.append(f'- {clean(key)}: {clean(status)}')
    out.extend(['','## CISA: exact KEV matches in supplied CVE report',''])
    if not report['matched_known_exploited_cves']:out.append('No exact KEV match from submitted vulnerability report; missing or stale input is not a clean bill of health.')
    for item in report['matched_known_exploited_cves']:
        out.append(f"- {clean(item['cve'])}: {clean(item['vendor'])} / {clean(item['product'])} (added {clean(item['date_added'])}); validate patch applicability and exposure.")
    out.extend(['','## CISA: asset inventory product-name hints (not confirmed vulnerabilities)',''])
    for x in report['inventory_name_hints_unverified']:
        out.append(f"- {clean(x['cve'])}: {clean(x['vendor'])} / {clean(x['product'])}; verify installed version and exposure before escalating.")
    out.extend(['','## Recent CISA KEV catalog additions',''])
    for row in report['recent_cisa_kev_entries']:
        out.append(f"- {clean(row['date_added'])}: {clean(row['cve'])} {clean(row['vendor'])} / {clean(row['product'])} (project applicability unverified).")
    out.extend(['','## Recent CISA advisories (titles only)',''])
    for item in report['cisa_advisory_headlines']:
        out.append(f"- {clean(item['published'])}: {clean(item['title'])}")
    out.extend(['','## OWASP VWAD: manual isolated benchmark candidates',''])
    for row in report['owasp_vwad_manual_lab_candidates']:
        out.append(f"- {clean(row['name'])} ({clean(row['slug'])}); select for manually approved offline lab only.")
    out.extend(['', 'No external applications were downloaded, executed or probed. No penetration testing was performed.', ''])
    return '\n'.join(out)


def main(argv=None):
    ap=argparse.ArgumentParser(description='CISA KEV + advisory and OWASP VWAD safe feed monitor')
    subs=ap.add_subparsers(dest='action',required=True)
    ref=subs.add_parser('refresh',help='Explicit HTTPS refresh of allowlisted official sources')
    ref.add_argument('--allow-network',action='store_true',help='Required explicit operator authorization for external HTTPS requests')
    ref.add_argument('--cache-dir',required=True)
    ref.add_argument('--repo-root',help='Audited repository root; defaults to discovered Git root or working directory')
    check=subs.add_parser('review',help='Offline comparison against supplied CVEs and safe lab directory')
    check.add_argument('--cache-dir',required=True)
    check.add_argument('--repo-root',help='Audited repository root; defaults to discovered Git root or working directory')
    check.add_argument('--vuln-report',help='Trivy JSON or CycloneDX JSON vulnerability report, user-supplied, read-only')
    check.add_argument('--inventory',help='Optional trusted local JSON list of vendor/product assets; name matching is only a review hint')
    check.add_argument('--technology',action='append',default=[],help='Filter OWASP lab candidates, exact technology tag')
    check.add_argument('--max-items',type=int,default=20)
    check.add_argument('--out',help='Existing private parent directory for report folder')
    args=ap.parse_args(argv)
    try:
        if args.action=='refresh':
            if not args.allow_network:raise ValueError('Network refresh requires explicit --allow-network')
            data=refresh(args.cache_dir,repo_root=args.repo_root)
            print(json.dumps(data,indent=2))
            return 3 if data['incomplete'] else 0
        if not 1<=args.max_items<=100:raise ValueError('max-items range is 1..100')
        data=review(args.cache_dir,args.vuln_report,args.technology,args.max_items,args.inventory,repo_root=args.repo_root)
        parent=Path(args.out).expanduser().resolve(strict=True) if args.out else Path(tempfile.gettempdir())
        if not parent.is_dir():raise ValueError('output parent must be a directory')
        folder=Path(tempfile.mkdtemp(prefix='sentinel-intel-',dir=parent))
        for name,contents in [('threat-intel.json',json.dumps(data,sort_keys=True,indent=2)),('threat-intel.md',markdown(data))]:
            fd=os.open(folder/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0),0o600)
            with os.fdopen(fd,'w',encoding='utf-8') as f:f.write(contents+'\n')
        print('Sentinel intelligence report:',folder)
        print('Feed coverage:',data['coverage'],'KEV exact matches:',len(data['matched_known_exploited_cves']))
        if data['matched_known_exploited_cves']:return 1
        if data['coverage']=='incomplete':return 3
        return 0
    except (ValueError,OSError,TypeError,json.JSONDecodeError) as exc:
        print('Sentinel threat intelligence error:',clean(type(exc).__name__+': '+str(exc),160),file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
