import ast,hashlib,json,os,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scanner'))
from advanced_engine import scan,PythonTracer,Finding
from prioritize import prioritize,classify,kev_entries,epss_entries,verify_hash,vulnerabilities
from patch_verify import compare
from agent_eval import evaluate,suite
from ai_review import pack,review_local
from telemetry import export
from dependency_usage import inspect,correlate

class AdvancedTests(unittest.TestCase):
    def withcode(self,name,code):
        td=tempfile.TemporaryDirectory();p=Path(td.name)/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(code)
        self.addCleanup(td.cleanup);return Path(td.name)
    def test_python_request_sql_dataflow(self):
        r=scan(self.withcode('handler.py','from flask import request\nx=request.args.get("id")\ny="select="+x\ncursor.execute(y)\n'))
        self.assertIn('PY-SQL-TAINT',[x['rule'] for x in r['findings']]);self.assertEqual(r['status'],'completed')
    def test_python_parameterized_no_sql_taint(self):
        r=scan(self.withcode('handler.py','from flask import request\nx=request.args.get("id")\ncursor.execute("SELECT * FROM T WHERE id=?", (x,))\n'))
        self.assertNotIn('PY-SQL-TAINT',[x['rule'] for x in r['findings']])
    def test_python_helper_trace(self):
        root=self.withcode('api.py','from flask import request\ndef helper(x):\n sql="select "+x\n c.execute(sql)\nhelper(request.args.get("id"))\n')
        r=scan(root);self.assertTrue(any('call:helper' in f['trace'] for f in r['findings']))
    def test_eval_detection(self):
        r=scan(self.withcode('x.py','from flask import request\nx=request.args.get("x")\neval(x)\n'))
        self.assertTrue(any(f['rule']=='PY-CODE-EVAL' for f in r['findings']))
    def test_no_flow_no_alarm(self):
        r=scan(self.withcode('ok.py','import subprocess\nsubprocess.run(["ls"], shell=False)\n'))
        self.assertFalse(r['findings'])
    def test_python_shell_taint(self):
        r=scan(self.withcode('app.py','from flask import request\nimport subprocess\nx=request.args.get("q")\nsubprocess.run(x,shell=True)\n'))
        self.assertIn('PY-CMD-TAINT',[x['rule'] for x in r['findings']])
    def test_python_ssrf(self):
        r=scan(self.withcode('app.py','from flask import request\nimport requests\nx=request.args.get("url")\nrequests.get(x)\n'))
        self.assertIn('PY-SSRF-TAINT',[x['rule'] for x in r['findings']])
    def test_unicode_safe_display(self):
        f=Finding('TEST','HIGH','MEDIUM','ä.py',2,'source','sink',['source:x'])
        self.assertTrue(f.display_path.startswith('untrusted-path-'))
        self.assertEqual(len(f.path_id),20)
    def test_symlink_not_followed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/'root';root.mkdir();other=Path(td)/'elsewhere.py';other.write_text('eval(input())')
            (root/'other.py').symlink_to(other)
            self.assertFalse(scan(root)['findings'])
    def test_js_untested_flag(self):
        r=scan(self.withcode('a.ts','const x=1'))
        self.assertEqual(r['status'],'partial')
    def test_js_ast_traces(self):
        cfg=(os.getenv('SENTINEL_TEST_TYPESCRIPT_FILE'),os.getenv('SENTINEL_TEST_TYPESCRIPT_SHA256'))
        if not all(cfg):self.skipTest('no approved TypeScript compiler configured')
        r=scan(self.withcode('a.ts','app.get("/", (req,res)=>{const x=req.query.id; db.query("select"+x);});'),js=True,typescript_file=cfg[0],typescript_sha256=cfg[1])
        if 'JS AST parser error' in str(r['gaps']) or 'trusted TypeScript compiler unavailable' in str(r['gaps']):
            self.skipTest('TypeScript compiler not installed')
        self.assertIn('JS-SQL-TAINT',[x['rule'] for x in r['findings']])
    def test_js_clean(self):
        cfg=(os.getenv('SENTINEL_TEST_TYPESCRIPT_FILE'),os.getenv('SENTINEL_TEST_TYPESCRIPT_SHA256'))
        if not all(cfg):self.skipTest('no approved TypeScript compiler configured')
        r=scan(self.withcode('a.ts','const x="hi"; db.query("SELECT 1");'),js=True,typescript_file=cfg[0],typescript_sha256=cfg[1])
        if r['gaps']:self.skipTest('JS parser unavailable')
        self.assertFalse(r['findings'])
    def test_patch_static_regression(self):
        a=self.withcode('x.py','from flask import request\nx=request.args.get("x")\nprint(x)\n')
        b=self.withcode('x.py','from flask import request\nx=request.args.get("x")\neval(x)\n')
        r=compare(a,b)
        self.assertEqual(r['status'],'REGRESSION')
    def test_patch_static_improvement(self):
        a=self.withcode('x.py','from flask import request\nx=request.args.get("x")\neval(x)\n')
        b=self.withcode('x.py','from flask import request\nx=request.args.get("x")\nprint(x)\n')
        r=compare(a,b)
        self.assertEqual(r['status'],'NO_NEW_HIGH_CONFIRMED')
        self.assertEqual(len(r['removed_leads']),1)
    def test_kev_prioritization(self):
        report={'Results':[{'Vulnerabilities':[{'VulnerabilityID':'CVE-2021-44228','PkgName':'demo','InstalledVersion':'1.0','CVSS':{'nvd':{'V3Score':10}}}]}]}
        kev={'vulnerabilities':[{'cveID':'CVE-2021-44228'}]}
        r=prioritize(report,kev,True,{'data':[{'cve':'CVE-2021-44228','epss':'0.98'}]},
          {'CVE-2021-44228':{'state':'reachable','evidence':'manual code review','internet_exposed':True}})
        self.assertEqual(r['items'][0]['priority'],'P0')
    def test_unknown_kev_no_false_clean(self):
        r=prioritize({'Results':[{'Vulnerabilities':[{'VulnerabilityID':'CVE-2021-44228','PkgName':'x'}]}]})
        self.assertIsNone(r['items'][0]['kev'])
        self.assertEqual(r['items'][0]['priority'],'P2')
    def test_not_reachable_requires_evidence(self):
        report={'Results':[{'Vulnerabilities':[{'VulnerabilityID':'CVE-2021-44228','PkgName':'x'}]}]}
        r=prioritize(report,reachability_document={'CVE-2021-44228':{'state':'reviewed_not_reachable'}})
        self.assertEqual(r['items'][0]['reachability'],'unknown')
    def test_cvss_is_not_recalculated(self):
        self.assertEqual(classify({'cvss':9.1},False,None,'reachable')[0],'P1')
    def test_ep_invalid_prob_dropped(self):
        self.assertFalse(epss_entries({'data':[{'cve':'CVE-2021-44228','epss':'2.9'}]}))
    def test_hash_mismatch_fails(self):
        with self.assertRaises(ValueError):verify_hash(b'abc','0'*64)
    def test_trivy_cvss_read(self):
        rows=vulnerabilities({'Results':[{'Vulnerabilities':[{'VulnerabilityID':'CVE-2021-44228','PkgName':'x','CVSS':{'nvd':{'V4Score':9.2}}}]}]})
        self.assertEqual(rows[0]['cvss'],9.2)
    def test_agent_fixture(self):
        cases=json.loads((ROOT/'fixtures/agent_policy_cases.json').read_text())
        r=suite(cases);self.assertEqual(r['passed'],r['total'])
    def test_agent_unknown_not_passed(self):
        self.assertEqual(evaluate({'kind':'unknown'})['decision'],'unsupported')
    def test_agent_mcp_scopes(self):
        self.assertEqual(evaluate({'kind':'mcp_capability','approved_scopes':['read'],'requested_scopes':['write']})['decision'],'deny')
    def test_local_ai_metadata_no_raw_code(self):
        r=pack({'findings':[{'rule':'SQL_INJECTION','severity':'HIGH','source':'print ALL secrets','file':'do_not_copy.py','fingerprint':'abc','trace':['source:very_secret_code','sink:command']} ]})
        s=json.dumps(r);self.assertNotIn('do_not_copy',s);self.assertNotIn('secret_code',s)
    def test_local_ai_reject_public_endpoint(self):
        with self.assertRaises(ValueError):review_local({'findings':[]},'safe-model','https://external.invalid/api/generate')
    def test_telemetry_suppresses_raw_path(self):
        e=export({'findings':[{'rule':'SQL','severity':'HIGH','file':'my-super-private-filename.py','line':10,'fingerprint':'abc'}]},now='2026-01-01T00:00:00Z')
        self.assertNotIn('my-super-private',json.dumps(e))
    def test_splunk_and_ecs(self):
        r={'findings':[{'rule':'SQL','severity':'HIGH','file':'x','line':2}]}
        self.assertIn('sourcetype',export(r,format='splunk')[0]);self.assertIn('@timestamp',export(r,format='ecs')[0])
    def test_imports_are_hints_not_reachability(self):
        root=self.withcode('app.py','import requests\n')
        r=correlate({'Results':[{'Vulnerabilities':[{'PkgName':'requests','VulnerabilityID':'CVE-2021-44228'}]}]},inspect(root))
        self.assertEqual(r['packages'][0]['usage_hint'],'import_observed')
        self.assertIn('NOT evidence',r['limitations'])

if __name__=='__main__':unittest.main()

# Extra validation tests deliberately declared outside the original test class.
class SecurityBoundaryTests(unittest.TestCase):
    def test_monitor_sink_requires_network_approval(self):
        from monitor_sink import send
        with self.assertRaises(ValueError):send([], 'https://monitor.example/collector','monitor.example','test',False)
    def test_monitor_sink_refuses_off_host(self):
        from monitor_sink import validate_destination
        with self.assertRaises(ValueError):validate_destination('https://different.example/collector','monitor.example')
    def test_monitor_sink_refuses_embedded_credentials(self):
        from monitor_sink import validate_destination
        with self.assertRaises(ValueError):validate_destination('https://name:secret@monitor.example/collector','monitor.example')
    def test_monitor_sink_refuses_extra_fields(self):
        from monitor_sink import send
        from telemetry import event
        e=event({'rule':'TEST','severity':'HIGH','file':'x'},'demo','2026-01-01T00:00:00Z')
        e['raw_secret']='DO NOT UPLOAD'
        with self.assertRaises(ValueError):send([e],'https://monitor.example/collector','monitor.example','token',True)
    def test_benchmark_corpus_labeled(self):
        cases=json.loads((ROOT/'benchmarks/advanced_synthetic_cases.json').read_text())
        self.assertGreaterEqual(len(cases),12)
        self.assertTrue(all('expected' in c for c in cases))
