#!/usr/bin/env python3
"""Generate offline CycloneDX 1.6 JSON file inventory for this source-only skill.

No package install, external network access, or trust assertion. This is a source-file
SBOM and does NOT enumerate dynamic system libraries or downloaded scanner binaries.
Run only during trusted release packaging, before SHA256SUMS generation.
"""
from pathlib import Path
import hashlib
import json

ROOT=Path(__file__).resolve().parents[1]
OUTPUT=ROOT/'sbom'/'sentinel-shield.cdx.json'

def make_sbom():
    files=sorted(p for p in ROOT.rglob('*') if p.is_file() and p.name!='SHA256SUMS' and p!=OUTPUT and '__pycache__' not in p.parts)
    return {
       'bomFormat':'CycloneDX','specVersion':'1.6','version':1,
       'metadata':{'component':{'type':'application','name':'sentinel-shield','version':'2.5.0','bom-ref':'pkg:generic/sentinel-shield@2.5.0'},
          'properties':[{'name':'sentinel:scope','value':'release source files only; external scanner binaries and environment not included'},
                        {'name':'sentinel:distribution-signature','value':'unsigned; publisher identity not attested'}]},
       'components':[{'type':'file','bom-ref':'file:'+p.relative_to(ROOT).as_posix(),
           'name':p.relative_to(ROOT).as_posix(),
           'hashes':[{'alg':'SHA-256','content':hashlib.sha256(p.read_bytes()).hexdigest()}]} for p in files],
       'dependencies':[{'ref':'pkg:generic/sentinel-shield@2.5.0','dependsOn':[]}]
    }

def main():
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(make_sbom(),indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print('Wrote source-only CycloneDX file inventory:',OUTPUT)

if __name__=='__main__':main()
