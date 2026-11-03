#!/usr/bin/env python3
"""Manifest verifier. SHA256SUMS digest MUST come from an independent trusted source."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as item:
        for part in iter(lambda:item.read(1024*1024),b''):h.update(part)
    return h.hexdigest()


def verify(root,expected_manifest_hash=None):
    manifest=root/'SHA256SUMS'
    if manifest.is_symlink() or not manifest.is_file():return False,'missing or symlink manifest'
    if expected_manifest_hash and (not re.fullmatch(r'[a-fA-F0-9]{64}',expected_manifest_hash) or digest(manifest)!=expected_manifest_hash.lower()):
        return False,'manifest digest does not match independently trusted expected digest'
    listed={}
    for raw in manifest.read_text(encoding='utf-8').splitlines():
        if not raw:continue
        m=re.fullmatch(r'([a-f0-9]{64})  (.+)',raw)
        if not m:return False,'malformed manifest entry'
        sha,name=m.groups()
        name_path=Path(name)
        if name_path.is_absolute() or name_path.as_posix() in listed or '..' in name_path.parts or name=='SHA256SUMS':
            return False,'duplicate or unsafe manifest path'
        listed[name]=sha
    actual=set()
    for parent, dirs, files in os.walk(root,followlinks=False):
        for name in dirs+files:
            path=Path(parent)/name
            if path.is_symlink():return False,'unexpected symlink in package'
            if path.is_file():
                rel=path.relative_to(root).as_posix()
                if rel!='SHA256SUMS':actual.add(rel)
            elif not path.is_dir():return False,'unexpected special file in package'
    if actual!=set(listed):
        return False,f'unlisted or missing package files: added={len(actual-set(listed))}, missing={len(set(listed)-actual)}'
    for name,expected in listed.items():
        path=root/name
        if not path.is_file() or not path.resolve().is_relative_to(root) or digest(path)!=expected:
            return False,'file digest mismatch'
    return True,f'checksums and complete file inventory passed for {len(listed)} files'


def main():
    parser=argparse.ArgumentParser(description='Verify installed Sentinel Shield skill against inventory and optional externally trusted manifest SHA256')
    parser.add_argument('--expected-manifest-sha256',help='SHA256 obtained outside this ZIP, e.g. from authenticated release information')
    args=parser.parse_args()
    valid,reason=verify(Path(__file__).resolve().parents[1],args.expected_manifest_sha256)
    print(reason,file=sys.stdout if valid else sys.stderr)
    return 0 if valid else 1

if __name__=='__main__':raise SystemExit(main())
