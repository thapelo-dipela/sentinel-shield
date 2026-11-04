"""Regression tests for crash, parser hijack and bounded-analysis review findings."""
import hashlib
import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import unittest
from pathlib import Path

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'scanner'))
from advanced_engine import scan, trusted_typescript_compiler, main


def trusted_compiler():
    """Optional independently configured test compiler; never discover from audited tree."""
    raw=os.environ.get('SENTINEL_TEST_TYPESCRIPT_FILE')
    digest=os.environ.get('SENTINEL_TEST_TYPESCRIPT_SHA256')
    if not raw or not digest or not Path(raw).is_file() or not shutil.which('node'):return None
    if hashlib.sha256(Path(raw).read_bytes()).hexdigest()!=digest:return None
    return raw,digest

class Alpha2RegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'project';self.root.mkdir()
    def put(self,relative,source):
        p=self.root/relative;p.parent.mkdir(exist_ok=True,parents=True);p.write_text(source);return p
    def test_bare_return_and_annotation_no_crash(self):
        self.put('handler.py','def regular():\n    y: int\n    return\n\nprint(regular())\n')
        r=scan(self.root)
        self.assertEqual(r['status'],'completed')
    def test_large_expression_does_not_crash(self):
        self.put('massive.py','x = '+'+'.join('1' for _ in range(5000))+'\n')
        r=scan(self.root)
        self.assertEqual(r['status'],'partial');self.assertTrue(r['gaps'])
    def test_file_failure_does_not_hide_other_lead(self):
        self.put('deep.py','x = '+'+'.join('1' for _ in range(5000))+'\n')
        self.put('vulnerable.py','from flask import request\ny=request.args.get("id")\neval(y)\n')
        r=scan(self.root)
        self.assertEqual(r['status'],'partial')
        self.assertIn('PY-CODE-EVAL',[x['rule'] for x in r['findings']])
    def test_analysis_budget_prevents_helper_explosion(self):
        helpers=['def f0(x):\n    return x\n']
        for i in range(1,6):helpers.append('def f%d(x):\n'%i+'\n'.join('    a%d=f%d(x)'%(j,i-1) for j in range(14))+'\n    return a13\n')
        self.put('helpers.py','\n'.join(helpers)+'\nfrom flask import request\nf5(request.args.get("n"))\n')
        r=scan(self.root);self.assertEqual(r['status'],'partial')
        self.assertTrue(any('budget' in gap for gap in r['gaps']))
    def test_helper_depth_gaps_not_completed(self):
        text='def f0(x):\n    return x\n'
        for i in range(1,13):text+=f'def f{i}(x):\n    return f{i-1}(x)\n'
        text+='\nfrom flask import request\nf12(request.args.get("x"))\n'
        self.put('deep_helpers.py',text)
        r=scan(self.root);self.assertEqual(r['status'],'partial')
        self.assertIn('depth',str(r['gaps']))
    def test_python_source_idioms(self):
        self.put('idioms.py', '''from flask import request
import requests

a = request.args.get('id').strip()
cur.execute('SELECT '+a)
b = request.get_json()
eval(b)
c = request.headers['X-Target']
requests.get(c)
with open(request.args.get('path')) as f:
    pass
for item in request.args.getlist('item'):
    cur.execute('SELECT '+item)
d = {}
d['test'] = request.args.get('s')
eval(d['test'])
r = [v for v in request.args.getlist('items')]
cur.execute('SELECT '+r[0])
''')
        r=scan(self.root)
        rules=[x['rule'] for x in r['findings']]
        for rule in ('PY-SQL-TAINT','PY-CODE-EVAL','PY-SSRF-TAINT','PY-PATH-TAINT'):
            self.assertIn(rule,rules)
    def test_numeric_conversion_is_not_sql_taint(self):
        self.put('convert.py','from flask import request\nx=int(request.args.get("id"))\ncur.execute("SELECT "+str(x))\n')
        self.assertNotIn('PY-SQL-TAINT',[x['rule'] for x in scan(self.root)['findings']])
    def test_async_request_payload(self):
        self.put('async.py','async def handler(request):\n    p=await request.json()\n    eval(p)\n')
        self.assertIn('PY-CODE-EVAL',[x['rule'] for x in scan(self.root)['findings']])
    def test_standard_library_smoke(self):
        lib=Path(sysconfig.get_paths()['stdlib'])
        choices=[lib/'fractions.py',lib/'textwrap.py',lib/'ipaddress.py']
        present=[p for p in choices if p.is_file()]
        if not present:self.skipTest('stdlib source unavailable')
        for p in present:shutil.copy2(p,self.root/p.name)
        r=scan(self.root)
        self.assertIsInstance(r['findings'],list)
        self.assertFalse(any('unexpected error' in g for g in r['gaps']))
    def test_cli_partial_exit_three_and_not_one(self):
        self.put('x.py','x = '+'+'.join('1' for _ in range(5000))+'\n')
        self.assertEqual(main(['--path',str(self.root)]),3)
    def test_js_requires_explicit_compiler(self):
        self.put('a.ts','const x=42')
        r=scan(self.root,js=True)
        self.assertEqual(r['status'],'partial')
        self.assertIn('JS AST failed:ValueError',r['gaps'])
    def test_refuses_compiler_inside_repo(self):
        p=self.put('node_modules/typescript/index.js','require("node:fs").writeFileSync("/tmp/planted", "bad")')
        with self.assertRaises(ValueError):trusted_typescript_compiler(self.root,str(p),hashlib.sha256(p.read_bytes()).hexdigest())
    def test_refuses_compiler_symlink(self):
        outside=Path(self.temp.name)/'trusted.js';outside.write_text('module.exports = 1')
        alias=Path(self.temp.name)/'alias.js';alias.symlink_to(outside)
        with self.assertRaises(ValueError):trusted_typescript_compiler(self.root,str(alias),hashlib.sha256(outside.read_bytes()).hexdigest())
    def test_hash_mismatch_rejected(self):
        p=Path(self.temp.name)/'typescript.js';p.write_text('exports.fake=1')
        with self.assertRaises(ValueError):trusted_typescript_compiler(self.root,str(p),'0'*64)
    def test_explicit_verified_compiler_and_hostile_nodemodules(self):
        cfg=trusted_compiler()
        if not cfg:self.skipTest('no independently approved test compiler configured')
        path,digest=cfg
        module=self.put('node_modules/typescript/index.js','require("node:fs").writeFileSync("'+str(Path(self.temp.name)/'injected-marker').replace('\\','/')+'","yes")')
        self.put('a.ts','app.get("/", (req,res)=>{ try { const x=req.query.user; db.query("SELECT "+x); } catch(e){} });')
        r=scan(self.root,js=True,typescript_file=path,typescript_sha256=digest)
        self.assertIn('JS-SQL-TAINT',[x['rule'] for x in r['findings']]);self.assertFalse((Path(self.temp.name)/'injected-marker').exists())
        # An excluded node_modules directory remains disclosed as a gap.
        self.assertEqual(r['status'],'partial')
    def test_js_try_for_switch_and_cast(self):
        cfg=trusted_compiler()
        if not cfg:self.skipTest('no trusted test compiler configured')
        path,digest=cfg
        self.put('a.ts','''app.get('/', (req, res) => {
  try {const x=req.query.id; db.query('SELECT ' + x);} catch(e) {}
  for (const item of req.body.ids) { db.query('SELECT ' + item); }
  switch(req.query.mode) { case 'x': db.query('SELECT ' + req.query.id); break; }
  db.query('SELECT '+parseInt(req.query.id));
});''')
        r=scan(self.root,js=True,typescript_file=path,typescript_sha256=digest)
        self.assertEqual(r['status'],'completed')
        sql=[x for x in r['findings'] if x['rule']=='JS-SQL-TAINT']
        self.assertEqual(len(sql),3)

class EvidenceRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
    def test_same_abstract_flow_different_location_not_dropped(self):
        p=self.root/'handler.py'
        p.write_text('from flask import request\nx=request.args.get("x")\neval(x)\nprint(x)\neval(x)\n')
        r=scan(self.root)
        flows=[x for x in r['findings'] if x['rule']=='PY-CODE-EVAL']
        self.assertEqual(len(flows),2)
        self.assertEqual(len({f['fingerprint'] for f in flows}),2)
    def test_line_move_keeps_fingerprint_and_code_change_invalidates(self):
        p=self.root/'handler.py'
        p.write_text('from flask import request\nx=request.args.get("x")\neval(x)\n')
        original=scan(self.root)['findings'][0]['fingerprint']
        p.write_text('from flask import request\nx=request.args.get("x")\npass\neval(x)\n')
        self.assertEqual(original,scan(self.root)['findings'][0]['fingerprint'])
        p.write_text('from flask import request\nx=request.args.get("x")\npass\neval( x + "!")\n')
        self.assertNotEqual(original,scan(self.root)['findings'][0]['fingerprint'])
    def test_real_stdlib_bounded_scan_no_abort(self):
        base=Path(sysconfig.get_paths()['stdlib'])
        if not base.is_dir() or len(list(base.glob('*.py')))<20:self.skipTest('Python stdlib not present')
        result=scan(base)
        self.assertIsInstance(result['findings'],list)
        self.assertIn(result['status'],('partial','completed'))
        self.assertFalse(any('unexpected error' in x for x in result['gaps']))

class JSInlineCallbackTests(unittest.TestCase):
    def test_expression_arrow_callback_sink(self):
        cfg=trusted_compiler()
        if not cfg:self.skipTest('trusted TypeScript compiler unavailable')
        with tempfile.TemporaryDirectory() as d:
            Path(d,'route.ts').write_text('app.get("/", (req,res) => db.query("SELECT "+req.query.id));')
            report=scan(Path(d),js=True,typescript_file=cfg[0],typescript_sha256=cfg[1])
            self.assertIn('JS-SQL-TAINT',[f['rule'] for f in report['findings']])
