"""
Architecture:

  policy_json
      │
      ▼
  json.loads()  ──── parse error ──▶  return {"error": ...}
      │
      ▼
  ┌──────────────────────────────────────────────────────┐
  │  _run_agent_loop()  — LLM drives tool selection      │
  │                                                      │
  │  user: "Analyse this policy ..."                     │
  │      │                                               │
  │      ▼                                               │
  │  LLM (claude-sonnet-4-6)                             │
  │      │  stop_reason = tool_use                       │
  │      ├─▶ check_wildcards(policy_json)        ──┐     │
  │      ├─▶ check_resource_scope(policy_json)   ──┤     │
  │      ├─▶ check_conditions(policy_json)       ──┼─── Python executes
  │      ├─▶ check_dangerous_combos(policy_json) ──┘     │
  │      │   [results appended to messages]              │
  │      ▼                                               │
  │  LLM calls submit_verdict(verdict, findings, reason) │
  │      → loop exits, verdict_data captured             │
  └──────────────────────────────────────────────────────┘
      │
      ├── STRONG ──▶  return result
      │
      └── WEAK ────▶  _remediate(policy_json, findings)
                          │
                          ▼
                      LLM generates fixed policy + change log
                          │
                          ▼
                      return result + remediation

Design rationale:
• Single agent, no sub-agents: analysing one JSON doc is one reasoning task. 
  Sub-agents add orchestration cost with no benefit here.
• Tools over pure prompting: Python tools give deterministic, auditable results the LLM cannot hallucinate. 
  The LLM's job is reasoning, not fact-extraction.
• submit_verdict as terminal tool: guarantees structured output; no brittle text-parsing of the final LLM response.
• Separate remediation call: prevents "eager remediator" failure — the LLM finishes analysis fully before attempting a fix.
• Claude Sonnet 4.6: strong JSON fidelity, best security reasoning in the Anthropic family.
• Prompt caching on system prompt: the system prompt is large and reusable;
"""

import json
import time
from typing import Any
import anthropic

MODEL  = "claude-sonnet-4-6"
_client = anthropic.Anthropic()   #reads ANTHROPIC_API_KEY from environment

MAX_LOOP_ITERATIONS = 12   #safety guard against runaway loops

#Classification Criteria
CLASSIFICATION_CRITERIA = """
WEAK — any single criterion is sufficient to classify as WEAK:
  W1. Wildcard action ("*" or "service:*") without tight resource AND condition constraints
  W2. Wildcard resource ("*") on write / admin / destructive actions
  W3. IAM privilege-escalation actions (iam:PassRole, iam:Create*, iam:Attach*,
      iam:Put*, iam:CreateAccessKey) without an MFA condition
  W4. NotAction or NotResource (inverted logic — easy to inadvertently allow broad access)
  W5. No Condition block on any high-risk statement (delete, write, IAM, KMS, STS, S3 Put)

STRONG — ALL of the following must hold:
  S1. Every action is explicitly listed (no wildcards)
  S2. Resources are specific ARNs (include account ID and resource path where applicable)
  S3. Every high-risk action has a Condition block (MFA, IP range, region, tag)
  S4. No privilege-escalation paths identifiable
"""

_SYSTEM_PROMPT = f"""You are a senior cloud security engineer specialising in AWS IAM.
Classify the given IAM policy as WEAK or STRONG by methodically using the provided tools.

{CLASSIFICATION_CRITERIA}

Required process (follow this order):
  1. call check_wildcards
  2. call check_resource_scope
  3. call check_conditions
  4. call check_dangerous_combos
  5. call submit_verdict with your conclusion

Do NOT call submit_verdict before running all four analysis tools.
If findings from early tools already prove the policy is WEAK, still run the remaining
tools to produce a complete picture before submitting."""

#Deterministic Analysis Tools
_HIGH_RISK_ACTIONS = frozenset({
    "iam:passrole", "iam:createuser", "iam:createaccesskey",
    "iam:attachuserpolicy", "iam:attachrolepolicy", "iam:attachgrouppolicy",
    "iam:putuserpolicy", "iam:putrolepolicy", "iam:putgrouppolicy",
    "iam:updateassumerolepolicy", "sts:assumerole",
    "kms:decrypt", "kms:reencryptfrom",
    "secretsmanager:getsecretvalue",
    "lambda:addpermission", "lambda:invokefunctionurl",
})

_SENSITIVE_SERVICES = frozenset({
    "iam", "sts", "kms", "secretsmanager", "ssm",
    "cloudtrail", "organizations", "account",
})


def _parse(policy_json: str) -> dict:
    try:
        return json.loads(policy_json)
    except json.JSONDecodeError as e:
        return {"_parse_error": str(e)}


def _to_list(val: Any) -> list:
    if isinstance(val, list):
        return val
    return [val] if val else []


def _allow_stmts(policy: dict) -> list[dict]:
    return [s for s in policy.get("Statement", []) if s.get("Effect", "Allow") == "Allow"]


def check_wildcards(policy_json: str) -> dict:
    """
    Detect wildcard (*) patterns in Action and Resource of Allow statements
    Returns a list of findings and a boolean flag
    """
    policy = _parse(policy_json)
    if "_parse_error" in policy:
        return {"error": policy["_parse_error"]}

    findings = []
    for stmt in _allow_stmts(policy):
        actions   = _to_list(stmt.get("Action",   []))
        resources = _to_list(stmt.get("Resource", []))

        wc_actions   = [a for a in actions   if a == "*" or str(a).endswith(":*")]
        wc_resources = [r for r in resources if r == "*"]

        if wc_actions:
            findings.append(f"Wildcard action(s): {wc_actions}  →  grants ALL matching permissions")
        if wc_resources:
            findings.append(f"Wildcard resource '*' paired with: {actions[:4]}")

    return {"findings": findings, "has_wildcards": bool(findings)}


def check_resource_scope(policy_json: str) -> dict:
    """
    Assess specificity of resource ARNs.
    Flags missing account IDs and overly broad patterns.
    """
    policy = _parse(policy_json)
    if "_parse_error" in policy:
        return {"error": policy["_parse_error"]}

    findings = []
    for stmt in _allow_stmts(policy):
        actions   = _to_list(stmt.get("Action",   []))
        resources = _to_list(stmt.get("Resource", []))

        for r in resources:
            if r == "*":
                findings.append(f"Resource '*' with actions {actions[:3]}")
                continue
            #For most services, a proper ARN has 6 colon-delimited parts;
            #a missing account-ID segment (index 4) is a scoping gap.
            if r.startswith("arn:aws:"):
                parts = r.split(":")
                service = parts[2] if len(parts) > 2 else ""
                account = parts[4] if len(parts) > 4 else ""
                if account == "" and service not in ("s3",):   # s3 global by design
                    findings.append(f"ARN missing account ID (applies to all accounts): {r}")

    return {
        "findings":           findings,
        "all_resources_specific": not findings,
    }


def check_conditions(policy_json: str) -> dict:
    """
    Check whether high-risk or broad Allow statements have Condition blocks.
    Specifically looks for missing MFA on privilege-escalation actions.
    """
    policy = _parse(policy_json)
    if "_parse_error" in policy:
        return {"error": policy["_parse_error"]}

    findings = []
    for stmt in _allow_stmts(policy):
        actions   = _to_list(stmt.get("Action",   []))
        resources = _to_list(stmt.get("Resource", []))
        condition = stmt.get("Condition", {})

        is_broad      = "*" in resources or any(a == "*" for a in actions)
        is_high_risk  = any(a.lower() in _HIGH_RISK_ACTIONS for a in actions)
        has_mfa       = "aws:MultiFactorAuthPresent" in json.dumps(condition)
        has_ip        = "aws:SourceIp" in json.dumps(condition)
        has_condition = bool(condition)

        if (is_broad or is_high_risk) and not has_condition:
            findings.append(
                f"Actions {actions[:3]} on {resources[:2]} — "
                f"no Condition block (no MFA, no IP, no region guard)"
            )
        elif is_high_risk and not has_mfa and not has_ip:
            findings.append(
                f"High-risk actions {actions[:3]} lack MFA or IP Condition"
            )

    return {
        "findings":              findings,
        "any_conditions_found":  any(
            "Condition" in s for s in _allow_stmts(policy)
        ),
    }


def check_dangerous_combos(policy_json: str) -> dict:
    """
    Detect privilege-escalation paths, NotAction/NotResource misuse,
    and dangerous cross-service combinations.
    """
    policy = _parse(policy_json)
    if "_parse_error" in policy:
        return {"error": policy["_parse_error"]}

    findings = []
    all_lower_actions: set[str] = set()
    has_not_action    = False
    has_not_resource  = False

    for stmt in policy.get("Statement", []):
        if stmt.get("Effect", "Allow") != "Allow":
            continue
        if "NotAction" in stmt:
            has_not_action = True
            not_list = _to_list(stmt["NotAction"])
            findings.append(
                f"NotAction used: allows EVERYTHING except {not_list[:3]} — "
                f"almost certainly overly permissive"
            )
        if "NotResource" in stmt:
            has_not_resource = True
            findings.append("NotResource used: applies the statement to all OTHER resources — high misconfiguration risk")

        actions = _to_list(stmt.get("Action", []))
        all_lower_actions.update(a.lower() for a in actions)

    escalation = all_lower_actions & _HIGH_RISK_ACTIONS
    if escalation:
        findings.append(f"Privilege-escalation / data-access actions present: {sorted(escalation)}")

    #flag sensitive-service wildcards
    for a in all_lower_actions:
        svc = a.split(":")[0] if ":" in a else ""
        if svc in _SENSITIVE_SERVICES and (a.endswith(":*") or a == "*"):
            findings.append(f"Wildcard on sensitive service: {a}")

    return {
        "findings":          findings,
        "has_not_action":    has_not_action,
        "has_not_resource":  has_not_resource,
        "escalation_risk":   bool(escalation),
    }


_TOOL_FUNCTIONS = {
    "check_wildcards":        check_wildcards,
    "check_resource_scope":   check_resource_scope,
    "check_conditions":       check_conditions,
    "check_dangerous_combos": check_dangerous_combos,
}

#Anthropic tool definitions
_TOOLS = [
    {
        "name": name,
        "description": fn.__doc__.strip().splitlines()[0],
        "input_schema": {
            "type": "object",
            "properties": {
                "policy_json": {
                    "type": "string",
                    "description": "The raw IAM policy JSON string"
                }
            },
            "required": ["policy_json"]
        }
    }
    for name, fn in _TOOL_FUNCTIONS.items()
] + [
    {
        "name": "submit_verdict",
        "description": (
            "Submit the final classification verdict. "
            "Call ONLY after running all four analysis tools."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": ["WEAK", "STRONG"],
                    "description": "The classification verdict"
                },
                "findings": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Specific issues (WEAK) or confirmed strengths (STRONG)"
                },
                "reason": {
                    "type": "string",
                    "description": "One concise sentence summarising the verdict"
                }
            },
            "required": ["verdict", "findings", "reason"]
        }
    }
]


#Agent Loop
def _run_agent_loop(policy_json: str) -> dict:
    """
    Drive the LLM tool-use loop until submit_verdict is called
    Returns the dict passed to submit_verdict
    """
    messages = [
        {
            "role": "user",
            "content": f"Analyse and classify this IAM policy:\n\n```json\n{policy_json}\n```",
        }
    ]

    for _ in range(MAX_LOOP_ITERATIONS):
        response = _client.messages.create(
            model=MODEL,
            max_tokens=2048,
            system=[
                {
                    "type": "text",
                    "text": _SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},  #avoid re-tokenising every iteration
                }
            ],
            tools=_TOOLS,
            messages=messages,
        )

        if response.stop_reason == "end_turn":
            #LLM stopped without calling submit_verdict — should not happen
            text = " ".join(b.text for b in response.content if hasattr(b, "text"))
            return {
                "verdict":  "WEAK",
                "findings": ["Agent loop ended without a formal verdict"],
                "reason":   text[:300],
            }

        #stop_reason == "tool_use"
        tool_results: list[dict] = []
        verdict_data: dict | None = None

        for block in response.content:
            if block.type != "tool_use":
                continue

            if block.name == "submit_verdict":
                verdict_data = block.input           #capture structured verdict
                tool_results.append({
                    "type":        "tool_result",
                    "tool_use_id": block.id,
                    "content":     json.dumps({"status": "verdict_recorded"}),
                })
            elif block.name in _TOOL_FUNCTIONS:
                result = _TOOL_FUNCTIONS[block.name](**block.input)
                tool_results.append({
                    "type":        "tool_result",
                    "tool_use_id": block.id,
                    "content":     json.dumps(result),
                })

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user",      "content": tool_results})

        if verdict_data:
            return verdict_data   # ← loop exits here

    return {
        "verdict":  "WEAK",
        "findings": ["Agent loop hit MAX_LOOP_ITERATIONS without a verdict"],
        "reason":   "Analysis incomplete",
    }


#Remediation
def _remediate(policy_json: str, findings: list[str], reason: str) -> dict:
    """
    Separate LLM call that generates a fixed policy. 
    Keeping this separate from the classification loop prevents the LLM from
    optimistically remediating before it has fully analysed the policy.
    """
    prompt = (
        f"The following AWS IAM policy was classified as WEAK.\n\n"
        f"Reason: {reason}\n\n"
        f"Findings:\n"
        + "\n".join(f"  - {f}" for f in findings)
        + f"\n\nOriginal policy:\n```json\n{policy_json}\n```\n\n"
        "Generate a remediated version that:\n"
        "1. Preserves the original intent as best it can be inferred\n"
        "2. Fixes every weakness above\n"
        "3. Is syntactically valid IAM JSON\n\n"
        "Respond with ONLY valid JSON in this exact structure:\n"
        '{"remediated_policy": {...}, "changes": ["change 1", "change 2", ...]}'
    )

    response = _client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=[
            {
                "type": "text",
                "text": (
                    "You are a senior AWS security engineer. "
                    "Output ONLY valid JSON — no prose, no markdown fences."
                ),
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[{"role": "user", "content": prompt}],
    )

    raw = response.content[0].text.strip()
    #Strip optional markdown code fences the model sometimes adds
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.rsplit("```", 1)[0]

    try:
        return json.loads(raw.strip())
    except json.JSONDecodeError:
        return {
            "remediated_policy": None,
            "changes":           [],
            "error":             "Could not parse remediation JSON — raw response attached",
            "raw":               raw[:500],
        }


#public API

def run_agent(policy_json: str) -> dict:
    """
    Classify an IAM policy and produce a remediated version if WEAK
    Returns:
    {
        "policy":         <original policy dict>,
        "classification": "WEAK" | "STRONG",
        "reason":         <one-sentence explanation>,
        "findings":       [<specific issue strings>],
        "remediation":    {"remediated_policy": {...}, "changes": [...]} | None,
        "elapsed_s":      <float>
    }
    """
    t0 = time.time()

    try:
        policy = json.loads(policy_json)
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {e}"}

    verdict_data = _run_agent_loop(policy_json)

    result = {
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


#demo
if __name__ == "__main__":
    demo_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect":   "Allow",
                "Action":   "*",
                "Resource": "*"
            }
        ]
    }, indent=2)

    print("Running agent on demo policy...\n")
    result = run_agent(demo_policy)
    print(json.dumps(result, indent=2))
