"""
Mirrors the structure of iam_agent.py exactly — same run_agent() interface,
same output schema, same tool-use loop pattern — but with GCP-specific tools
and classification criteria.

GCP IAM binding format (input):
{
  "bindings": [
    {
      "role":    "roles/storage.objectViewer",
      "members": ["serviceAccount:sa@project.iam.gserviceaccount.com"],
      "condition": {          ← optional
        "title":      "Prod bucket only",
        "expression": "resource.name.startsWith('projects/_/buckets/prod-')"
      }
    }
  ]
}

Key AWS → GCP conceptual mapping:
  AWS Statement.Action   ≈  GCP binding.role      (what is allowed)
  AWS Statement.Resource ≈  GCP resource hierarchy (where it applies)
  AWS Condition block    ≈  GCP binding.condition  (CEL expression)
  AWS Principal          ≈  GCP binding.members    (who gets the role)

Architecture — identical to iam_agent.py:
  policy_json
      │
      ▼
  validate bindings structure
      │
      ▼
  _run_agent_loop()  (LLM + 4 GCP tools → submit_verdict)
      │
      ├── STRONG ──▶ return result
      └── WEAK   ──▶ _remediate() → fixed bindings + change log
"""

import json
import time
from typing import Any
import anthropic

MODEL   = "claude-sonnet-4-6"
_client = anthropic.Anthropic()

MAX_LOOP_ITERATIONS = 12

#Classification Criteria
GCP_CLASSIFICATION_CRITERIA = """
WEAK — any single criterion is sufficient:
  G1. Primitive role (roles/owner, roles/editor, roles/viewer) on any binding
  G2. allUsers or allAuthenticatedUsers as a member in any binding
      (makes the resource fully or broadly public)
  G3. High-risk IAM roles (serviceAccountTokenCreator, serviceAccountAdmin,
      organizationAdmin, securityAdmin, projectIamAdmin) without a Condition
  G4. Broad service-admin roles (compute.admin, storage.admin, bigquery.admin, etc.)
      granted to a service account with no Condition restricting scope

STRONG — all must hold:
  S1. Only predefined (non-primitive) or custom roles (projects/P/roles/R)
  S2. No public members (allUsers / allAuthenticatedUsers absent)
  S3. Specific, identifiable member identifiers in every binding
  S4. Every sensitive or broad binding has a Condition block
"""

_GCP_SYSTEM_PROMPT = f"""You are a senior cloud security engineer specialising in GCP IAM.
Classify the given GCP IAM binding set as WEAK or STRONG using the provided tools.

{GCP_CLASSIFICATION_CRITERIA}

Required process (follow this order):
  1. call gcp_check_primitive_roles
  2. call gcp_check_public_members
  3. call gcp_check_sensitive_roles
  4. call gcp_check_conditions
  5. call submit_verdict

Do NOT submit a verdict before running all four analysis tools."""

#GCP Sensitive Role Lists

_PRIMITIVE_ROLES = frozenset({
    "roles/owner",
    "roles/editor",
    "roles/viewer",
})

_HIGH_RISK_ROLES = frozenset({
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.securityAdmin",
    "roles/iam.workloadIdentityPoolAdmin",
    "roles/resourcemanager.organizationAdmin",
    "roles/resourcemanager.folderAdmin",
    "roles/resourcemanager.projectIamAdmin",
})

_BROAD_SERVICE_ADMINS = frozenset({
    "roles/compute.admin",
    "roles/storage.admin",
    "roles/bigquery.admin",
    "roles/cloudsql.admin",
    "roles/container.admin",
    "roles/run.admin",
    "roles/cloudfunctions.admin",
    "roles/dataproc.admin",
})

_PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})


def _parse(policy_json: str) -> dict:
    try:
        return json.loads(policy_json)
    except json.JSONDecodeError as e:
        return {"_parse_error": str(e)}


def _bindings(policy: dict) -> list[dict]:
    return policy.get("bindings", [])


#Deterministic GCP Analysis Tools
def gcp_check_primitive_roles(policy_json: str) -> dict:
    """
    Detect primitive roles (roles/owner, roles/editor, roles/viewer).
    Primitive roles are coarse-grained and violate least-privilege (G1).
    """
    policy = _parse(policy_json)
    if "_parse_error" in policy:
        return {"error": policy["_parse_error"]}

    findings = []
    for b in _bindings(policy):
        role = b.get("role", "")
        if role in _PRIMITIVE_ROLES:
            members = b.get("members", [])
            findings.append(
                f"Primitive role '{role}' granted to: {members}  "
                f"— violates least-privilege; use a predefined or custom role"
            )

    return {"findings": findings, "has_primitive_roles": bool(findings)}


def gcp_check_public_members(policy_json: str) -> dict:
    """
    Detect allUsers or allAuthenticatedUsers — makes resources publicly accessible (G2).
    """
    policy = _parse(policy_json)
    if "_parse_error" in policy:
        return {"error": policy["_parse_error"]}

    findings = []
    for b in _bindings(policy):
        role    = b.get("role", "")
        members = b.get("members", [])
        public  = [m for m in members if m in _PUBLIC_MEMBERS]
        if public:
            findings.append(
                f"Role '{role}' granted to PUBLIC member(s) {public}  "
                f"— resource is accessible without authentication"
            )

    return {"findings": findings, "has_public_members": bool(findings)}


def gcp_check_sensitive_roles(policy_json: str) -> dict:
    """
    Detect high-risk IAM roles and broad service-admin roles (G3 + G4).
    """
    policy = _parse(policy_json)
    if "_parse_error" in policy:
        return {"error": policy["_parse_error"]}

    findings = []
    for b in _bindings(policy):
        role      = b.get("role", "")
        members   = b.get("members", [])
        condition = b.get("condition")

        if role in _HIGH_RISK_ROLES:
            sa_members = [m for m in members if m.startswith("serviceAccount:")]
            findings.append(
                f"High-risk role '{role}' granted to {members}  "
                f"{'(no condition)' if not condition else '(has condition — check adequacy)'}"
            )

        if role in _BROAD_SERVICE_ADMINS:
            sa_members = [m for m in members if m.startswith("serviceAccount:")]
            if sa_members:
                findings.append(
                    f"Broad admin role '{role}' granted to service account(s) {sa_members}  "
                    f"{'without condition — high lateral movement risk' if not condition else '(condition present)'}"
                )

    return {"findings": findings, "has_sensitive_roles": bool(findings)}


def gcp_check_conditions(policy_json: str) -> dict:
    """
    Check whether sensitive or broad bindings have Condition blocks (CEL expressions).
    GCP conditions are equivalent to AWS Condition blocks.
    """
    policy = _parse(policy_json)
    if "_parse_error" in policy:
        return {"error": policy["_parse_error"]}

    findings    = []
    any_conditions = False

    sensitive_roles = _PRIMITIVE_ROLES | _HIGH_RISK_ROLES | _BROAD_SERVICE_ADMINS

    for b in _bindings(policy):
        role      = b.get("role", "")
        members   = b.get("members", [])
        condition = b.get("condition")

        if condition:
            any_conditions = True

        if role in sensitive_roles and not condition:
            findings.append(
                f"Sensitive role '{role}' on {members} has NO condition — "
                f"no resource, time, or IP restriction"
            )

    return {
        "findings":         findings,
        "any_conditions":   any_conditions,
        "unconditioned_sensitive_bindings": len(findings),
    }


_GCP_TOOL_FUNCTIONS = {
    "gcp_check_primitive_roles": gcp_check_primitive_roles,
    "gcp_check_public_members":  gcp_check_public_members,
    "gcp_check_sensitive_roles": gcp_check_sensitive_roles,
    "gcp_check_conditions":      gcp_check_conditions,
}

#Anthropic tool definitions for GCP tools
_GCP_TOOLS = [
    {
        "name":        name,
        "description": fn.__doc__.strip().splitlines()[0],
        "input_schema": {
            "type": "object",
            "properties": {
                "policy_json": {
                    "type":        "string",
                    "description": "The raw GCP IAM binding set JSON string"
                }
            },
            "required": ["policy_json"]
        }
    }
    for name, fn in _GCP_TOOL_FUNCTIONS.items()
] + [
    {
        "name":        "submit_verdict",
        "description": "Submit the final verdict. Call ONLY after running all four GCP analysis tools.",
        "input_schema": {
            "type": "object",
            "properties": {
                "verdict":  {"type": "string", "enum": ["WEAK", "STRONG"]},
                "findings": {"type": "array", "items": {"type": "string"}},
                "reason":   {"type": "string"}
            },
            "required": ["verdict", "findings", "reason"]
        }
    }
]


#Agent Loop
def _run_agent_loop(policy_json: str) -> dict:
    messages = [
        {
            "role":    "user",
            "content": f"Analyse and classify this GCP IAM binding set:\n\n```json\n{policy_json}\n```",
        }
    ]

    for _ in range(MAX_LOOP_ITERATIONS):
        response = _client.messages.create(
            model=MODEL,
            max_tokens=2048,
            system=[{"type": "text", "text": _GCP_SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
            tools=_GCP_TOOLS,
            messages=messages,
        )

        if response.stop_reason == "end_turn":
            text = " ".join(b.text for b in response.content if hasattr(b, "text"))
            return {"verdict": "WEAK", "findings": ["Loop ended without verdict"], "reason": text[:300]}

        tool_results:  list[dict] = []
        verdict_data:  dict | None = None

        for block in response.content:
            if block.type != "tool_use":
                continue
            if block.name == "submit_verdict":
                verdict_data = block.input
                tool_results.append({
                    "type": "tool_result", "tool_use_id": block.id,
                    "content": json.dumps({"status": "verdict_recorded"}),
                })
            elif block.name in _GCP_TOOL_FUNCTIONS:
                result = _GCP_TOOL_FUNCTIONS[block.name](**block.input)
                tool_results.append({
                    "type": "tool_result", "tool_use_id": block.id,
                    "content": json.dumps(result),
                })

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user",      "content": tool_results})

        if verdict_data:
            return verdict_data

    return {"verdict": "WEAK", "findings": ["MAX_LOOP_ITERATIONS reached"], "reason": "Incomplete"}


#Remediation
def _remediate(policy_json: str, findings: list[str], reason: str) -> dict:
    prompt = (
        f"The following GCP IAM binding set was classified as WEAK.\n\n"
        f"Reason: {reason}\n\n"
        f"Findings:\n" + "\n".join(f"  - {f}" for f in findings) +
        f"\n\nOriginal binding set:\n```json\n{policy_json}\n```\n\n"
        "Generate a remediated version that:\n"
        "1. Preserves the original intent\n"
        "2. Replaces primitive roles with appropriate predefined roles\n"
        "3. Removes public members or scopes them with conditions\n"
        "4. Adds Condition blocks where needed\n\n"
        "Respond with ONLY valid JSON:\n"
        '{"remediated_policy": {"bindings": [...]}, "changes": ["change 1", ...]}'
    )

    response = _client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=[{"type": "text",
                 "text": "You are a senior GCP security engineer. Output ONLY valid JSON, no prose.",
                 "cache_control": {"type": "ephemeral"}}],
        messages=[{"role": "user", "content": prompt}],
    )

    raw = response.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.rsplit("```", 1)[0]

    try:
        return json.loads(raw.strip())
    except json.JSONDecodeError:
        return {"remediated_policy": None, "changes": [], "error": "Parse failed", "raw": raw[:500]}


#Public API (same signature as iam_agent.run_agent)
def run_agent(policy_json: str) -> dict:
    """
    Classify a GCP IAM binding set and (if WEAK) produce a remediated version.
    Returns the same schema as iam_agent.run_agent() for uniform downstream handling.
    """
    t0 = time.time()

    try:
        policy = json.loads(policy_json)
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {e}"}

    if "bindings" not in policy:
        return {"error": "Not a GCP IAM binding set — 'bindings' key missing"}

    verdict_data = _run_agent_loop(policy_json)

    result = {
        "provider":       "gcp",
        "policy":         policy,
        "classification": verdict_data["verdict"],
        "reason":         verdict_data.get("reason", ""),
        "findings":       verdict_data.get("findings", []),
        "remediation":    None,
        "elapsed_s":      round(time.time() - t0, 2),
    }

    if verdict_data["verdict"] == "WEAK":
        result["remediation"] = _remediate(
            policy_json,
            verdict_data.get("findings", []),
            verdict_data.get("reason", ""),
        )
        result["elapsed_s"] = round(time.time() - t0, 2)

    return result
