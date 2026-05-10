"""
Runs the agent on 8 labelled policies, then prints:
  • Per-policy verdict table with match indicator and elapsed time
  • Agreement rate and average latency time
  • A sample remediation for the first WEAK policy
"""

import json
import time
from iam_agent import run_agent

#Evaluation Dataset (5 WEAK + 3 STRONG)
EVAL_POLICIES = {
    "admin_wildcard": {
        "label":       "WEAK",
        "description": "Full admin — Action:* Resource:* (W1 + W2)",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"}
            ]
        }
    },

    "s3_service_wildcard": {
        "label":       "WEAK",
        "description": "All S3 actions on all resources, no conditions (W1 + W5)",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
            ]
        }
    },

    "iam_escalation_no_mfa": {
        "label":       "WEAK",
        "description": "IAM privilege-escalation actions without MFA condition (W3)",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect":   "Allow",
                    "Action":   ["iam:PassRole", "iam:AttachUserPolicy", "iam:CreateAccessKey"],
                    "Resource": "*"
                }
            ]
        }
    },

    "notaction_trap": {
        "label":       "WEAK",
        "description": "NotAction grants everything except listed actions (W4)",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect":    "Allow",
                    "NotAction": ["iam:*", "organizations:*"],
                    "Resource":  "*"
                }
            ]
        }
    },

    "dynamodb_no_conditions": {
        "label":       "WEAK",
        "description": "DynamoDB full access, no resource constraint, no conditions (W1 + W5)",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"}
            ]
        }
    },

    "s3_specific_readonly": {
        "label":       "STRONG",
        "description": "Specific S3 read on named bucket, region condition",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect":    "Allow",
                    "Action":    ["s3:GetObject", "s3:ListBucket"],
                    "Resource":  [
                        "arn:aws:s3:::my-app-prod-bucket",
                        "arn:aws:s3:::my-app-prod-bucket/*"
                    ],
                    "Condition": {
                        "StringEquals": {"aws:RequestedRegion": "us-east-1"}
                    }
                }
            ]
        }
    },

    "developer_role": {
        "label":       "STRONG",
        "description": "Scoped developer — EC2 + CloudWatch, tagged resource, MFA",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect":    "Allow",
                    "Action":    ["ec2:DescribeInstances", "ec2:StartInstances", "ec2:StopInstances"],
                    "Resource":  "arn:aws:ec2:us-east-1:123456789012:instance/*",
                    "Condition": {
                        "StringEquals":     {"ec2:ResourceTag/Team": "dev"},
                        "Bool":             {"aws:MultiFactorAuthPresent": "true"}
                    }
                },
                {
                    "Effect":   "Allow",
                    "Action":   ["logs:GetLogEvents", "logs:DescribeLogGroups"],
                    "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:/app/*"
                }
            ]
        }
    },

    "secrets_with_mfa": {
        "label":       "STRONG",
        "description": "KMS decrypt + SecretsManager get, specific ARNs, MFA required",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["kms:Decrypt", "secretsmanager:GetSecretValue"],
                    "Resource": [
                        "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123def456",
                        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-*"
                    ],
                    "Condition": {
                        "Bool": {"aws:MultiFactorAuthPresent": "true"}
                    }
                }
            ]
        }
    },
}


#Runner
def run_evaluation() -> None:
    results = []
    first_weak_result = None   #keep the first WEAK result for a remediation sample

    print("  IAM CLASSIFICATION AGENT — EVALUATION RUN")
    print(f"\n  {'Policy':<30} {'Expected':<10} {'Got':<10} {'Match':<7} {'Time (s)'}")

    for name, case in EVAL_POLICIES.items():
        policy_json = json.dumps(case["policy"])
        result      = run_agent(policy_json)

        predicted = result.get("classification", "ERROR")
        expected  = case["label"]
        match     = predicted == expected
        elapsed   = result.get("elapsed_s", 0)

        mark = "OK" if match else "FAIL"
        print(f"  {name:<30} {expected:<10} {predicted:<10} {mark:<7} {elapsed:.1f}")

        results.append({
            "name":      name,
            "expected":  expected,
            "predicted": predicted,
            "match":     match,
            "elapsed":   elapsed,
            "result":    result,
        })

        if expected == "WEAK" and first_weak_result is None:
            first_weak_result = result

    #Summary
    correct   = sum(r["match"]   for r in results)
    total     = len(results)
    avg_time  = sum(r["elapsed"] for r in results) / total

    print(f"  Agreement rate : {correct}/{total}  ({correct/total:.0%})")
    print(f"  Avg latency    : {avg_time:.1f} s")

    #Sample remediation
    if first_weak_result and first_weak_result.get("remediation"):
        rem = first_weak_result["remediation"]
        print("\n  SAMPLE REMEDIATION  (first WEAK policy)\n")
        print("  Reason:   ", first_weak_result["reason"])
        print("  Findings:")
        for f in first_weak_result["findings"]:
            print(f"    • {f}")
        print("\n  Changes made:")
        for c in rem.get("changes", []):
            print(f"    → {c}")
        print("\n  Remediated policy:")
        print("  " + json.dumps(rem.get("remediated_policy"), indent=4).replace("\n", "\n  "))

    #Detailed findings for failures
    failures = [r for r in results if not r["match"]]
    if failures:
        print(f"  MISCLASSIFICATIONS ({len(failures)}):")
        for r in failures:
            print(f"\n  [{r['name']}]  expected={r['expected']}  got={r['predicted']}")
            for f in r["result"].get("findings", []):
                print(f"    • {f}")
    else:
        print("\n  All policies correctly classified.")


if __name__ == "__main__":
    run_evaluation()
