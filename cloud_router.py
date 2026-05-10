"""
Single entry point for any supported cloud provider.
Auto-detects the provider from the policy JSON shape, then
delegates to the appropriate agent.

Supported providers:
  AWS  - detected by presence of top-level "Statement" key
  GCP  — detected by presence of top-level "bindings" key

Adding Azure would mean:
  1. Write azure_agent.py with the same run_agent() interface
  2. Add an "azure" branch in detect_provider()
  3. Import and call it in classify_policy()
  -> No changes to existing AWS or GCP agents.

note: this router pattern means each provider is a self-contained module.
Providers are open for extension, closed for modification.
"""

import json

from iam_agent import run_agent as _aws_agent
from gcp_agent import run_agent as _gcp_agent


def detect_provider(policy_json: str) -> str:
    """
    Infer the cloud provider from the top-level JSON keys.

    Returns "aws", "gcp", or "unknown".
    O(1) — just a key presence check, no schema validation.
    """
    try:
        policy = json.loads(policy_json)
    except json.JSONDecodeError:
        return "unknown"

    if "Statement" in policy:
        return "aws"
    if "bindings" in policy:
        return "gcp"
    return "unknown"


def classify_policy(policy_json: str) -> dict:
    """
    Classify any supported cloud IAM policy.

    The returned dict always contains:
      provider        — "aws" | "gcp"
      classification  — "WEAK" | "STRONG"
      reason          — one-sentence explanation
      findings        — list of specific issues
      remediation     — fixed policy + change log (only if WEAK)
      elapsed_s       — wall-clock time
    """
    provider = detect_provider(policy_json)

    if provider == "aws":
        result = _aws_agent(policy_json)
        result["provider"] = "aws"
        return result

    if provider == "gcp":
        return _gcp_agent(policy_json)   #already sets provider = "gcp"

    return {
        "provider":       "unknown",
        "error":          (
            "Unrecognised policy format — expected an AWS policy "
            "('Statement' key) or a GCP binding set ('bindings' key)"
        ),
    }
