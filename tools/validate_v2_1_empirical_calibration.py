#!/usr/bin/env python3
from pathlib import Path
import json, subprocess, sys, tempfile
ROOT=Path(__file__).resolve().parents[1]
def fail(m): print("[FAIL]",m); raise SystemExit(1)
def ok(m): print("[PASS]",m)
required=["classification/v2_1_calibration_policy.json","corpus/v2_1_empirical/manifest.json","corpus/v2_1_empirical/README.md","docs/v2.1-empirical-evidence-calibration.md","tools/v2_1_calibration_report.py"]
for rel in required:
    if not (ROOT/rel).is_file(): fail("missing "+rel)
ok("empirical calibration files are present")
policy=json.loads((ROOT/required[0]).read_text())
if policy.get("mode")!="measurement_only" or policy.get("automatic_weight_changes") is not False: fail("unsafe policy")
if not all(policy.get("protected_scope",{}).values()): fail("protected scope incomplete")
ok("measurement-only policy and protected scope are enforced")
fixture=[{"host":"192.0.2.10","classification":{"device_family":{"label":"printer","confidence":68,"confidence_band":"possible","decision":"review","evidence_ids":["printer_ipp"],"contradictions":[],"secondary_candidates":[{"label":"web_endpoint"}],"uncertainty_reasons":["independence_group_cap"]}}}]
truth={"labels":[{"host":"192.0.2.10","expected_family":"printer","source":"sanitized-network-a"}]}
with tempfile.TemporaryDirectory() as d:
    d=Path(d); (d/"analysis.json").write_text(json.dumps(fixture)); (d/"labels.json").write_text(json.dumps(truth))
    outs=[]
    for i in (1,2):
        out=d/f"r{i}.json"; outs.append(out)
        subprocess.run([sys.executable,str(ROOT/"tools/v2_1_calibration_report.py"),"--input",str(d/"analysis.json"),"--labels",str(d/"labels.json"),"--profiles",str(ROOT/"classification/evidence_profiles.json"),"--policy",str(ROOT/"classification/v2_1_calibration_policy.json"),"--output-json",str(out)],cwd=ROOT,check=True,stdout=subprocess.PIPE,text=True)
    if outs[0].read_bytes()!=outs[1].read_bytes(): fail("report not deterministic")
    report=json.loads(outs[0].read_text())
    if report["labeled_outcomes"]["axis_accuracy"]!=1.0: fail("accuracy incorrect")
    if report["calibration_readiness"]["automatic_weight_changes"] is not False: fail("unsafe readiness")
ok("deterministic report and labeled outcomes validated")
manifest=json.loads((ROOT/"corpus/v2_1_empirical/manifest.json").read_text())
if manifest.get("entries")!=[]: fail("installer invented corpus entries")
ok("empirical corpus starts empty")
print("[PASS] NetSniper v2.1 empirical evidence calibration validator complete")
