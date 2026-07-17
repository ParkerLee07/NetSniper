#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, statistics
from collections import Counter
from pathlib import Path
from typing import Any

def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))

def discover(values):
    out=set()
    for raw in values:
        p=Path(raw).expanduser().resolve()
        if p.is_file(): out.add(p)
        elif p.is_dir():
            if (p/"analysis.json").is_file(): out.add((p/"analysis.json").resolve())
            out.update(x.resolve() for x in p.rglob("analysis.json") if x.is_file())
        else: raise SystemExit(f"Input does not exist: {p}")
    return sorted(out)

def records(payload):
    if isinstance(payload,list): return [x for x in payload if isinstance(x,dict)]
    if isinstance(payload,dict):
        for key in ("hosts","devices","records","analysis"):
            if isinstance(payload.get(key),list): return [x for x in payload[key] if isinstance(x,dict)]
        return [payload]
    return []

def host(rec):
    for key in ("host","ip","address","ipv4"):
        if isinstance(rec.get(key),str) and rec[key].strip(): return rec[key].strip()
    return "unknown-host"

def axes(rec):
    containers=[rec]
    for key in ("classification","classifications","identity"):
        if isinstance(rec.get(key),dict): containers.append(rec[key])
    seen=set()
    for c in containers:
        for name,val in c.items():
            if isinstance(val,dict) and id(val) not in seen and "decision" in val and ("label" in val or "confidence" in val):
                seen.add(id(val)); yield str(name),val

def contribution_map(payload):
    out={}
    def walk(v):
        if isinstance(v,dict):
            eid=next((v.get(k) for k in ("evidence_id","id") if isinstance(v.get(k),str)),None)
            if eid:
                for k in ("score","weight","points","value","confidence"):
                    n=v.get(k)
                    if isinstance(n,(int,float)) and not isinstance(n,bool):
                        out.setdefault(str(eid),float(n)); break
            for child in v.values(): walk(child)
        elif isinstance(v,list):
            for child in v: walk(child)
    walk(payload); return out

def labels(path):
    if not path: return {}
    p=load(Path(path)); vals=p.get("labels",[]) if isinstance(p,dict) else p
    return {x["host"]:x for x in vals if isinstance(x,dict) and isinstance(x.get("host"),str)}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--input",action="append",required=True)
    ap.add_argument("--labels")
    ap.add_argument("--profiles",default="classification/evidence_profiles.json")
    ap.add_argument("--policy",default="classification/v2_1_calibration_policy.json")
    ap.add_argument("--output-json",required=True)
    ap.add_argument("--output-markdown")
    a=ap.parse_args()
    files=discover(a.input)
    if not files: raise SystemExit("No analysis JSON files found.")
    policy=load(Path(a.policy)); weights=contribution_map(load(Path(a.profiles))); truth=labels(a.labels)
    decisions=Counter(); bands=Counter(); ev=Counter(); attrib=Counter(); contradictions=Counter(); uncertainty=Counter(); secondary=Counter()
    conf=[]; hosts=0; axis_total=0; labeled_total=0; labeled_correct=0; confusion=Counter(); labeled_hosts=set(); sources=set()
    for f in files:
        for rec in records(load(f)):
            hosts+=1; hk=host(rec); lab=truth.get(hk)
            if lab:
                labeled_hosts.add(hk)
                if isinstance(lab.get("source"),str): sources.add(lab["source"])
            for name,axis in axes(rec):
                axis_total+=1; decisions[str(axis.get("decision","unknown"))]+=1; bands[str(axis.get("confidence_band","none"))]+=1
                if isinstance(axis.get("confidence"),int): conf.append(axis["confidence"])
                ids=axis.get("evidence_ids",[]) if isinstance(axis.get("evidence_ids"),list) else []
                for eid in ids:
                    eid=str(eid); ev[eid]+=1
                    if eid in weights: attrib[eid]+=weights[eid]
                for x in axis.get("contradictions",[]) if isinstance(axis.get("contradictions"),list) else []: contradictions[str(x)]+=1
                for x in axis.get("uncertainty_reasons",[]) if isinstance(axis.get("uncertainty_reasons"),list) else []: uncertainty[str(x)]+=1
                for x in axis.get("secondary_candidates",[]) if isinstance(axis.get("secondary_candidates"),list) else []:
                    secondary[str(x.get("label","unknown") if isinstance(x,dict) else x)]+=1
                if lab:
                    expected_key={"device_family":"expected_family","family":"expected_family","platform":"expected_platform"}.get(name)
                    if expected_key and isinstance(lab.get(expected_key),str):
                        expected=lab[expected_key]; actual=str(axis.get("label","unknown")); labeled_total+=1
                        if expected==actual: labeled_correct+=1
                        else: confusion[(expected,actual)]+=1
    min_h=int(policy["minimum_labeled_hosts_before_weight_proposal"]); min_n=int(policy["minimum_distinct_networks_before_weight_proposal"]); min_s=int(policy["minimum_samples_per_evidence_id"])
    eligible=sorted(k for k,v in ev.items() if v>=min_s)
    report={
      "schema_version":"netsniper-v2.1-calibration-report-v1",
      "dataset_summary":{"analysis_files":len(files),"hosts":hosts,"axis_results":axis_total,"labeled_hosts":len(labeled_hosts),"distinct_label_sources":len(sources)},
      "decision_distribution":dict(decisions.most_common()),
      "confidence_distribution":{"bands":dict(bands.most_common()),"count":len(conf),"minimum":min(conf) if conf else None,"maximum":max(conf) if conf else None,"mean":statistics.fmean(conf) if conf else None,"median":statistics.median(conf) if conf else None},
      "evidence_frequency":dict(ev.most_common()),
      "evidence_attribution":{"declared_contributions_recovered":len(weights),"declared_contribution_totals":dict(attrib.most_common()),"unweighted_observed_evidence":sorted(set(ev)-set(weights))},
      "contradiction_frequency":dict(contradictions.most_common()),
      "review_trigger_frequency":dict(uncertainty.most_common()),
      "secondary_candidate_frequency":dict(secondary.most_common()),
      "labeled_outcomes":{"axis_total":labeled_total,"axis_correct":labeled_correct,"axis_accuracy":labeled_correct/labeled_total if labeled_total else None,"confusion_pairs":[{"expected":e,"actual":a,"count":c} for (e,a),c in confusion.most_common()]},
      "calibration_readiness":{"measurement_only":True,"automatic_weight_changes":False,"minimum_labeled_hosts":min_h,"minimum_distinct_networks":min_n,"minimum_samples_per_evidence_id":min_s,"eligible_evidence_ids":eligible,"labeled_host_threshold_met":len(labeled_hosts)>=min_h,"network_diversity_threshold_met":len(sources)>=min_n,"ready_for_weight_proposal":len(labeled_hosts)>=min_h and len(sources)>=min_n and bool(eligible)}
    }
    Path(a.output_json).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    if a.output_markdown:
        lines=["# NetSniper v2.1 Calibration Report",""]
        for k,v in report.items():
            if k=="schema_version": continue
            lines += [f"## {k.replace('_',' ').title()}","","```json",json.dumps(v,indent=2,sort_keys=True),"```",""]
        Path(a.output_markdown).write_text("\n".join(lines),encoding="utf-8")
    print(json.dumps(report["calibration_readiness"],sort_keys=True))
if __name__=="__main__": main()
