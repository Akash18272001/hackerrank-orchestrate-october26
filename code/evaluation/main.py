#!/usr/bin/env python3
"""Run the public-sample evaluator without regenerating the hidden output."""
from pathlib import Path
import sys
CODE_DIR = Path(__file__).resolve().parents[1]
ROOT = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))
import main as solution

def run():
    identities = solution.load_csv("user_identities.csv")
    audits = solution.load_csv("user_audit_log.csv")
    manifest = solution.load_csv("evidence_files.csv")
    observations = solution.build_observations(manifest)
    requests = solution.load_csv("sample_deletion_requests.csv")
    results = []
    for request in requests:
        status, steps, _ = solution.classify_case(request, identities, audits, observations)
        results.append({"case_id": request["case_id"], "deletion_status": status, "steps_json": solution.json_steps(steps)})
    report = solution.run_evaluation(results)
    print(f"Public sample requests: {report['sample_count']}")
    print(f"Status matches: {report['status_matches']}/{report['sample_count']}")
    print(f"Exact step matches: {report['exact_step_matches']}/{report['sample_count']}")
    for cid, expected, generated, detail in report["mismatches"][:20]:
        print(f"{cid}: expected={expected}, generated={generated}; {detail}")
    return 0

if __name__ == "__main__":
    raise SystemExit(run())
