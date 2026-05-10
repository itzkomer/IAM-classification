"""
Run through cloud_router so the test proves end-to-end multi-cloud routing.
"""

import json
from cloud_router import classify_policy, detect_provider

#Evaluation Dataset (3 WEAK + 2 STRONG)
GCP_EVAL_POLICIES = {
    "owner_to_user": {
        "label":       "WEAK",
        "description": "Primitive roles/owner granted to a user (G1)",
        "policy": {
            "bindings": [
                {
                    "role":    "roles/owner",
                    "members": ["user:alice@example.com"]
                }
            ]
        }
    },

    "public_storage_bucket": {
        "label":       "WEAK",
        "description": "allUsers given storage.objectViewer — public bucket (G2)",
        "policy": {
            "bindings": [
                {
                    "role":    "roles/storage.objectViewer",
                    "members": ["allUsers"]
                },
                {
                    "role":    "roles/storage.objectAdmin",
                    "members": ["serviceAccount:backend@myproject.iam.gserviceaccount.com"]
                }
            ]
        }
    },

    "sa_token_creator_no_condition": {
        "label":       "WEAK",
        "description": "serviceAccountTokenCreator — privilege escalation path, no condition (G3)",
        "policy": {
            "bindings": [
                {
                    "role":    "roles/iam.serviceAccountTokenCreator",
                    "members": ["serviceAccount:ci-runner@myproject.iam.gserviceaccount.com"]
                }
            ]
        }
    },

    "scoped_logging_writer": {
        "label":       "STRONG",
        "description": "logs.logWriter to specific SA — non-primitive, no escalation risk",
        "policy": {
            "bindings": [
                {
                    "role":    "roles/logging.logWriter",
                    "members": ["serviceAccount:app@myproject.iam.gserviceaccount.com"],
                    "condition": {
                        "title":      "Prod logs only",
                        "description": "Restrict to production log buckets",
                        "expression": "resource.name.startsWith('projects/myproject/logs/prod-')"
                    }
                }
            ]
        }
    },

    "storage_viewer_with_condition": {
        "label":       "STRONG",
        "description": "storage.objectViewer to SA with resource condition — no public access",
        "policy": {
            "bindings": [
                {
                    "role":    "roles/storage.objectViewer",
                    "members": ["serviceAccount:reader@myproject.iam.gserviceaccount.com"],
                    "condition": {
                        "title":      "Prod bucket only",
                        "expression": "resource.name.startsWith('projects/_/buckets/prod-data')"
                    }
                }
            ]
        }
    },
}


#Runner
def run_gcp_evaluation() -> None:
    results = []
    first_weak_result = None

    print("  GCP IAM CLASSIFICATION AGENT — EVALUATION RUN")
    print(f"\n  {'Policy':<35} {'Expected':<10} {'Got':<10} {'Match':<7} {'Time (s)'}")

    for name, case in GCP_EVAL_POLICIES.items():
        policy_json = json.dumps(case["policy"])

        #verify routing works before the API call
        detected = detect_provider(policy_json)
        assert detected == "gcp", f"Router mis-detected {name} as {detected}"

        result    = classify_policy(policy_json)
        predicted = result.get("classification", "ERROR")
        expected  = case["label"]
        match     = predicted == expected
        elapsed   = result.get("elapsed_s", 0)

        mark = "OK" if match else "FAIL"
        print(f"  {name:<35} {expected:<10} {predicted:<10} {mark:<7} {elapsed:.1f}")

        results.append({"name": name, "expected": expected, "predicted": predicted,
                         "match": match, "elapsed": elapsed, "result": result})

        if expected == "WEAK" and first_weak_result is None:
            first_weak_result = result

    #summary
    correct  = sum(r["match"]   for r in results)
    total    = len(results)
    avg_time = sum(r["elapsed"] for r in results) / total

    print(f"  Agreement rate : {correct}/{total}  ({correct/total:.0%})")
    print(f"  Avg latency    : {avg_time:.1f} s")

    #sample remediation
    if first_weak_result and first_weak_result.get("remediation"):
        rem = first_weak_result["remediation"]
        print("\n  SAMPLE REMEDIATION  (first WEAK GCP policy)\n")
        print("  Reason:", first_weak_result["reason"])
        print("  Findings:")
        for f in first_weak_result.get("findings", []):
            print(f"    • {f}")
        print("\n  Changes made:")
        for c in rem.get("changes", []):
            print(f"    → {c}")
        print("\n  Remediated policy:")
        print("  " + json.dumps(rem.get("remediated_policy"), indent=4).replace("\n", "\n  "))

    #failures
    failures = [r for r in results if not r["match"]]
    if failures:
        print(f"\n  MISCLASSIFICATIONS ({len(failures)}):")
        for r in failures:
            print(f"  [{r['name']}] expected={r['expected']} got={r['predicted']}")
            for f in r["result"].get("findings", []):
                print(f"    • {f}")
    else:
        print("\n  All GCP policies correctly classified.")


if __name__ == "__main__":
    run_gcp_evaluation()
