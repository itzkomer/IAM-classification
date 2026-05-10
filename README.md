# Multi-Cloud IAM Classification Agent

This project implements an agentic security system designed to analyze, classify, and remediate Identity and Access Management (IAM) policies across multiple cloud providers. The system combines the reasoning capabilities of Large Language Models (LLMs) with deterministic Python tools to ensure high accuracy and auditability.

---

## System Architecture

The project follows a modular **Router Pattern**, allowing it to scale across different cloud environments while maintaining a unified interface.

### 1. Cloud Router

The `cloud_router.py` acts as the single entry point. It performs $O(1)$ provider detection by inspecting the top-level JSON keys:

* 
**AWS:** Detected via the `"Statement"` key.


* 
**GCP:** Detected via the `"bindings"` key.



### 2. Provider Agents (AWS & GCP)

Each provider has a dedicated agent (e.g., `iam_agent.py`, `gcp_agent.py`) that follows a controlled analysis loop:

* 
**Deterministic Tools:** Python functions extract objective facts (wildcards, resource scopes, sensitive roles) to prevent LLM hallucinations.


* 
**LLM Orchestration:** A Claude-powered agent iterates through these tools, requiring a full suite of tests before submitting a verdict.


* 
**Remediation:** To avoid "eager remediator" failure, the system completes the full classification before initiating a separate call to generate a fixed policy and change log.



---

## Classification Criteria

Policies are classified as **WEAK** or **STRONG** based on provider-specific security standards:

| Cloud | WEAK Criteria (Examples) | STRONG Criteria |
| --- | --- | --- |
| **AWS** | Wildcard actions/resources without conditions (W1/W2), missing MFA on privilege escalation (W3), or use of `NotAction` (W4). | Explicit actions, specific ARNs, and mandatory conditions (MFA/IP/Region) for high-risk tasks. |
| **GCP** | Primitive roles (Owner/Editor) , public access (`allUsers`) , or unconditioned sensitive roles.

 | Predefined or custom roles only, no public members, and specific identifiers with CEL conditions.

 |

---

## Evaluation Results

The system has been validated against a dataset of 13 policies (8 AWS, 5 GCP) covering common misconfigurations and hardened standards.

* 
**AWS Accuracy:** 100% ($8/8$ policies correctly identified).


* 
**GCP Accuracy:** 100% ($5/5$ policies correctly identified).


* 
**Total Agreement:** 100%.



---

## Getting Started

### Prerequisites

* Python 3.10+
* Anthropic API Key (configured in environment as `ANTHROPIC_API_KEY`)

### Running Evaluations

To run the AWS-specific evaluation:

```bash
python eval_runner.py

```

To run the GCP and Multi-Cloud routing evaluation:

```bash
python gcp_eval.py

```

### Adding a New Provider (e.g., Azure)

The architecture is **open for extension but closed for modification**. To add Azure:

1. Create `azure_agent.py` implementing the `run_agent()` interface.
2. Update `detect_provider()` in `cloud_router.py` to recognize Azure-specific keys.
3. Import the agent into the router. **No changes to AWS or GCP logic are required.**

---

## Project Structure

* `cloud_router.py`: Main entry point and provider detection.
* `iam_agent.py`: AWS-specific analysis and remediation logic.
* `gcp_agent.py`: GCP-specific analysis and remediation logic.
* `eval_runner.py` / `gcp_eval.py`: Testing suites and evaluation datasets.
