"""
DeploySense Risk Pipeline — Standalone script for GitHub Actions.

Takes entity GUID + account ID + tokens as inputs, runs the full pipeline:
  1. Fetch deployments (30 days)
  2. Fetch entity details + related entities
  3. Enrich deployments with violations + anomalies (parallel)
  4. Fetch code patches for violated deployments (parallel)
  5. Fetch code patches for target deployment
  6. Build structured LLM prompt
  7. Call Claude for risk analysis

Outputs markdown risk analysis to stdout (for GH Action to post as PR comment).

Usage:
    python scripts/risk_pipeline.py \
        --entity-guid "MTA4ODg2MjN8QVBNfEFQUExJQ0FUSU9OfDY5OTM0MzA3" \
        --account-id 10888623 \
        --timestamp-ms 1781196340360 \
        --nr-api-key "NRAK-..." \
        --ghe-token "ghp_..." \
        --llm-token "NCT-..." \
        --target-index 0
"""

import argparse
import asyncio
import json
import os
import re
import statistics
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import httpx

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

NERD_GRAPH_HOST = "https://nerd-graph.staging-service.nr-ops.net"
REQUEST_TIMEOUT = 120
THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000
WINDOW_AFTER_DEPLOY_MS = 2 * 60 * 60 * 1000
MAX_CONCURRENT = 5

# Globals set from args
API_KEY = ""
GHE_TOKEN = ""
LLM_TOKEN = ""
LLM_URL = "https://nerd-completion.staging-service.nr-ops.net"


# ══════════════════════════════════════════════════════════════════════════════
# NERDGRAPH HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def get_request_headers() -> Dict[str, str]:
    return {
        "Api-Key": API_KEY,
        "Content-Type": "application/json",
        "NewRelic-Requesting-Services": "testing",
        "X-Login-Context": "",
        "X-Query-Source-Capability-Id": "NRAI",
    }


async def query_nerdgraph(query: str, variables: Optional[Dict] = None) -> dict:
    headers = get_request_headers()
    url = f"{NERD_GRAPH_HOST}/graphql"
    body: Dict[str, Any] = {"query": query}
    if variables:
        body["variables"] = variables
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, headers=headers, json=body, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
    return resp.json()


async def query_nrql(nrql: str, account_id: int) -> List[dict]:
    var = {"nrqlQuery": nrql, "accountId": account_id, "timeout": 60}
    query = """
    query NRQLQuery($accountId: Int!, $nrqlQuery: Nrql!, $timeout: Seconds) {
      actor { account(id: $accountId) { nrql(query: $nrqlQuery, timeout: $timeout) { results } } }
    }"""
    try:
        data = await query_nerdgraph(query, var)
        return data.get("data", {}).get("actor", {}).get("account", {}).get("nrql", {}).get("results") or []
    except Exception as e:
        print(f"[NRQL Error] {e}", file=sys.stderr)
        return []


def ms_to_str(ts_ms: int) -> str:
    try:
        return datetime.fromtimestamp(ts_ms / 1000).strftime("%Y-%m-%d %H:%M:%S")
    except:
        return "?"


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1+2: FETCH DEPLOYMENTS
# ══════════════════════════════════════════════════════════════════════════════

async def fetch_deployments(entity_guid: str, timestamp_ms: int, account_id: int) -> List[Dict]:
    since_ms = timestamp_ms - THIRTY_DAYS_MS
    nrql = (
        f"SELECT changeTrackingId, timestamp, deployment_result, version, "
        f"`entity.guid`, `entity.name`, gheOrg, gheRepo, team, environment, "
        f"commit, changelog, type, user, groupId, configurationVersion, deployMechanism "
        f"FROM ChangeTrackingEvent "
        f"WHERE category = 'Deployment' AND deployment_phase = 'end' "
        f"AND `entity.guid` = '{entity_guid}' "
        f"SINCE {since_ms} UNTIL {timestamp_ms} LIMIT MAX"
    )
    print(f"[Step 1] Fetching deployments...", file=sys.stderr)
    rows = await query_nrql(nrql, account_id)
    deployments = []
    for row in rows:
        deployments.append({
            "changeTrackingId": row.get("changeTrackingId"),
            "timestamp_ms": row.get("timestamp"),
            "timestamp_str": ms_to_str(row.get("timestamp", 0)),
            "entity_guid": row.get("entity.guid"),
            "entity_name": row.get("entity.name"),
            "version": row.get("version"),
            "deployment_result": row.get("deployment_result"),
            "user": row.get("user"),
            "commit": row.get("commit"),
            "changelog": row.get("changelog"),
            "team": row.get("team"),
            "environment": row.get("environment"),
            "gheOrg": row.get("gheOrg"),
            "gheRepo": row.get("gheRepo"),
            "groupId": row.get("groupId"),
            "type": row.get("type"),
            "deployMechanism": row.get("deployMechanism"),
            "root_entity_alert_violations": [],
            "root_entity_anomalies": {},
            "related_entities": [],
        })
    print(f"[Step 1] Found {len(deployments)} deployments.", file=sys.stderr)
    return deployments


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3: FETCH ENTITY + RELATIONSHIPS
# ══════════════════════════════════════════════════════════════════════════════

ENTITY_QUERY = """
query EntityAndRelationships($entityGuid: EntityGuid!) {
  actor {
    entity(guid: $entityGuid) {
      accountId domain type name alertSeverity permalink guid
      goldenMetrics { metrics { name metricName definition { select from where facet } } }
      relationshipTraversal(hops: 1, limit: 50) {
        results {
          type
          source { guid entity { guid name alertSeverity accountId domain type } }
          target { guid entity { guid name alertSeverity accountId domain type } }
        }
      }
    }
  }
}"""

SUPPORTED_RELS = {"CALLS", "CONNECTS_TO", "CONSUMES", "CONTAINS", "HOSTS", "PRODUCES", "SERVES"}


async def fetch_entity_and_related(entity_guid: str) -> Tuple[Dict, Dict[str, Dict]]:
    data = await query_nerdgraph(ENTITY_QUERY, {"entityGuid": entity_guid})
    entity_data = data.get("data", {}).get("actor", {}).get("entity", {})
    root = {
        "guid": entity_data.get("guid"),
        "name": entity_data.get("name"),
        "accountId": entity_data.get("accountId"),
        "domain": entity_data.get("domain"),
        "type": entity_data.get("type"),
        "goldenMetrics": entity_data.get("goldenMetrics"),
    }
    related = {}
    for rel in (entity_data.get("relationshipTraversal") or {}).get("results", []):
        if rel.get("type") not in SUPPORTED_RELS:
            continue
        for side in ("source", "target"):
            ent = rel[side].get("entity", {})
            guid = ent.get("guid")
            if guid and guid != entity_guid and guid not in related:
                related[guid] = ent
    print(f"[Step 3] Entity: {root['name']}, Related: {len(related)}", file=sys.stderr)
    return root, related


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4: ENRICH WITH VIOLATIONS (PARALLEL)
# ══════════════════════════════════════════════════════════════════════════════

VIOLATIONS_QUERY = """
query GetViolations($guid: EntityGuid!, $startTime: EpochMilliseconds!, $endTime: EpochMilliseconds!) {
  actor { entity(guid: $guid) { alertViolations(startTime: $startTime, endTime: $endTime) { closedAt label level openedAt } alertSeverity } }
}"""


async def fetch_violations(entity_guid: str, start_ms: int, end_ms: int) -> List[Dict]:
    try:
        data = await query_nerdgraph(VIOLATIONS_QUERY, {"guid": entity_guid, "startTime": start_ms, "endTime": end_ms})
        entity = data.get("data", {}).get("actor", {}).get("entity") or {}
        violations = entity.get("alertViolations") or []
        for v in violations:
            if v.get("openedAt"):
                v["openedAt"] = ms_to_str(v["openedAt"])
            if v.get("closedAt"):
                v["closedAt"] = ms_to_str(v["closedAt"])
        return violations
    except:
        return []


async def enrich_deployment(dep: Dict, root_entity: Dict, related_map: Dict, account_id: int) -> Dict:
    deploy_ts = dep.get("timestamp_ms", 0)
    start_ms = deploy_ts
    end_ms = deploy_ts + WINDOW_AFTER_DEPLOY_MS
    violations = await fetch_violations(root_entity["guid"], start_ms, end_ms)
    dep["root_entity_alert_violations"] = violations
    # Fetch related entity info
    related_results = []
    for guid, ent in related_map.items():
        related_results.append(ent)
    dep["related_entities"] = related_results
    return dep


async def enrich_all_parallel(deployments: List[Dict], root_entity: Dict, related_map: Dict, account_id: int) -> List[Dict]:
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    async def enrich_with_limit(dep):
        async with semaphore:
            return await enrich_deployment(dep, root_entity, related_map, account_id)

    print(f"[Step 4] Enriching {len(deployments)} deployments (parallel)...", file=sys.stderr)
    t0 = time.perf_counter()
    results = await asyncio.gather(*[enrich_with_limit(d) for d in deployments])
    print(f"[Step 4] Done in {time.perf_counter() - t0:.1f}s", file=sys.stderr)
    return list(results)


# ══════════════════════════════════════════════════════════════════════════════
# STEP 5: FETCH CODE PATCHES FROM GHE (PARALLEL)
# ══════════════════════════════════════════════════════════════════════════════

async def ghe_get(path: str) -> Optional[Dict]:
    if not GHE_TOKEN:
        return None
    url = f"https://source.datanerd.us/api/v3{path}"
    headers = {"Authorization": f"token {GHE_TOKEN}", "Accept": "application/vnd.github.v3+json"}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            return resp.json()
    except:
        return None


def parse_changelog_url(url: str) -> Optional[Dict]:
    if not url:
        return None
    m = re.match(r"https://source\.datanerd\.us/([^/]+)/([^/]+)/releases/tag/(.+)", url)
    if m:
        return {"org": m.group(1), "repo": m.group(2), "tag": m.group(3)}
    return None


async def fetch_patches_from_changelog(changelog_url: str) -> Dict:
    parsed = parse_changelog_url(changelog_url)
    if not parsed:
        return {"error": "Cannot parse URL"}
    org, repo, tag = parsed["org"], parsed["repo"], parsed["tag"]
    tags = await ghe_get(f"/repos/{org}/{repo}/tags?per_page=30")
    if not tags:
        return {"error": "Cannot fetch tags"}
    tag_names = [t["name"] for t in tags]
    try:
        idx = tag_names.index(tag)
        prev_tag = tag_names[idx + 1] if idx + 1 < len(tag_names) else None
    except ValueError:
        prev_tag = None
    if not prev_tag:
        return {"error": "No previous tag"}
    compare = await ghe_get(f"/repos/{org}/{repo}/compare/{prev_tag}...{tag}")
    if not compare:
        return {"error": "Compare failed"}
    files = compare.get("files", [])
    commits = compare.get("commits", [])
    return {
        "tag": tag, "previous_tag": prev_tag,
        "total_commits": len(commits),
        "commit_messages": [c.get("commit", {}).get("message", "").split("\n")[0] for c in commits],
        "files_changed": len(files),
        "lines_added": sum(f.get("additions", 0) for f in files),
        "lines_removed": sum(f.get("deletions", 0) for f in files),
        "files": [{"filename": f["filename"], "additions": f.get("additions", 0),
                   "deletions": f.get("deletions", 0), "status": f.get("status", ""),
                   "patch": f.get("patch", "")} for f in files],
    }


async def fetch_patches_from_commit(org: str, repo: str, sha: str) -> Dict:
    data = await ghe_get(f"/repos/{org}/{repo}/commits/{sha}")
    if not data:
        return {"error": "Cannot fetch commit"}
    files = data.get("files", [])
    commit_info = data.get("commit", {})
    return {
        "commit": sha[:12],
        "commit_messages": [commit_info.get("message", "").split("\n")[0]],
        "total_commits": 1,
        "files_changed": len(files),
        "lines_added": data.get("stats", {}).get("additions", 0),
        "lines_removed": data.get("stats", {}).get("deletions", 0),
        "files": [{"filename": f["filename"], "additions": f.get("additions", 0),
                   "deletions": f.get("deletions", 0), "status": f.get("status", ""),
                   "patch": f.get("patch", "")} for f in files],
    }


async def fetch_patches_for_deploy(dep: Dict, semaphore: asyncio.Semaphore) -> None:
    async with semaphore:
        if dep.get("code_patches") and "error" not in dep.get("code_patches", {}):
            return
        changelog = dep.get("changelog", "")
        if changelog:
            patches = await fetch_patches_from_changelog(changelog)
            if "error" not in patches:
                dep["code_patches"] = patches
                return
        commit = dep.get("commit", "")
        ghe_org = dep.get("gheOrg", "")
        ghe_repo = dep.get("gheRepo", "")
        if commit and ghe_org and ghe_repo:
            patches = await fetch_patches_from_commit(ghe_org, ghe_repo, commit)
            if "error" not in patches:
                dep["code_patches"] = patches
                return
        dep["code_patches"] = {"error": "No source available"}


async def fetch_all_patches_parallel(deployments: List[Dict]) -> None:
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    print(f"[Step 5] Fetching code patches for {len(deployments)} deployments (parallel)...", file=sys.stderr)
    t0 = time.perf_counter()
    await asyncio.gather(*[fetch_patches_for_deploy(d, semaphore) for d in deployments])
    fetched = sum(1 for d in deployments if d.get("code_patches") and "error" not in d.get("code_patches", {}))
    print(f"[Step 5] Done in {time.perf_counter() - t0:.1f}s — {fetched}/{len(deployments)} fetched", file=sys.stderr)


# ══════════════════════════════════════════════════════════════════════════════
# STEP 6: BUILD LLM PROMPT
# ══════════════════════════════════════════════════════════════════════════════

def build_prompt(target: Dict, all_deploys: List[Dict]) -> str:
    dep = target
    history = [d for d in all_deploys if d.get("changeTrackingId") != dep.get("changeTrackingId")]
    broken = [d for d in history if len(d.get("root_entity_alert_violations", [])) > 0]
    failed = [d for d in history if d.get("deployment_result") == "failure" and d not in broken]
    clean = [d for d in history if d not in broken and d not in failed]
    problem = broken + failed

    day_of_week = ""
    try:
        day_of_week = datetime.fromtimestamp(dep.get("timestamp_ms", 0) / 1000).strftime("%A")
    except:
        pass

    prompt = """You are an expert Principal Site Reliability Engineer (SRE), Infrastructure Architect, and Risk Analysis AI. Your task is to evaluate an upcoming, pre-deployment software release, compare it systematically against historical deployment data, assign risk scores based on concrete patterns, and provide actionable engineering recommendations.

You must evaluate both the current and historical deployments across these 5 core dimensions:
1. Files changed (Core application logic vs. Non-core configuration/manifests)
2. Code diff size (Micro vs. Moderate vs. Massive scale changes)
3. Code diff semantics (Contextual and operational risk of the actual code changes, dependency bumps, or architectural mutations)
4. Time of deployment (Temporal risks including peak traffic hours, end of week, or operational blackouts)
5. Blast radius (Potential downstream impact on connected services, event streams, or uninstrumented datastores)

Here is the structured context for your analysis:

"""

    # <current_deployment_metadata>
    prompt += f"""<current_deployment_metadata>
## DEPLOYMENT UNDER REVIEW (PRE-DEPLOY — outcome unknown)
Service: {dep.get('entity_name', '?')}
Entity GUID: {dep.get('entity_guid', '?')}
Version: {dep.get('version', '?')}
Deployer: {dep.get('user', '?')}
Planned deploy time: {day_of_week} {dep.get('timestamp_str', '?')}
Target environment: {dep.get('environment', '?')}
Team: {dep.get('team', '?')}
Repo: {dep.get('gheOrg', '')}/{dep.get('gheRepo', '')}
Deploy Mechanism: {dep.get('deployMechanism', '?')}

NOTE: This deployment has NOT shipped yet. You are evaluating it BEFORE it goes to production. You do NOT know its outcome.

## RELATED ENTITIES (potential blast radius)
"""
    related = dep.get("related_entities", [])
    if related:
        prompt += f"{len(related)} connected service(s):\n"
        for rel in related:
            prompt += f"- {rel.get('name', '?')} ({rel.get('domain', '?')}/{rel.get('type', '?')})\n"
    prompt += "</current_deployment_metadata>\n\n\n"

    # <current_deployment_code_changes>
    prompt += "<current_deployment_code_changes>\n"
    patches = dep.get("code_patches", {})
    if patches and "error" not in patches:
        files = patches.get("files", [])
        prompt += f"""Tag: {patches.get('tag', patches.get('commit', '?'))}
Previous tag: {patches.get('previous_tag', 'N/A')}
Total commits in release: {patches.get('total_commits', '?')}
Files changed: {len(files)}
Lines added: +{patches.get('lines_added', 0)}, Lines removed: -{patches.get('lines_removed', 0)}

### Commit messages:
"""
        for msg in patches.get("commit_messages", [])[:10]:
            prompt += f"- {msg}\n"
        prompt += "\n### Modified files:\n"
        for f in files:
            prompt += f"- {f['filename']} (+{f['additions']} -{f['deletions']}) [{f['status']}]\n"
        prompt += "\n### Code patches:\n"
        chars = 0
        for f in files:
            p = f.get("patch", "")
            if not p:
                continue
            if chars + len(p) > 8000:
                prompt += "\n[... truncated]\n"
                break
            prompt += f"```diff\n// {f['filename']}\n{p}\n```\n"
            chars += len(p)
    else:
        prompt += "Code patches not available.\n"
    prompt += "</current_deployment_code_changes>\n\n\n"

    # <historical_deployment_outcomes>
    prompt += f"""<historical_deployment_outcomes>
Total previous deploys: {len(history)}
Infrastructure failures: {len(failed)}
Deploys that caused alerts: {len(broken)}
Clean deploys: {len(clean)}
"""
    if problem:
        prompt += "\n### Previous deploys that CAUSED PROBLEMS:\n"
        for i, d in enumerate(problem[:8], 1):
            violations = d.get("root_entity_alert_violations", [])
            prompt += f"""
{i}. **{d.get('version', '?')}** ({d.get('timestamp_str', '?')}) — {d.get('deployment_result', '?').upper()}
   - Deployer: {d.get('user', '?')}
   - Commit: {(d.get('commit') or '?')[:12]}
   - Environment: {d.get('environment', '?')}
   - Alert violations: {len(violations)}
"""
            for v in violations[:3]:
                prompt += f"     - [{v.get('level', '?')}] {v.get('label', '?')} (opened: {v.get('openedAt', '?')})\n"
    if clean:
        prompt += "\n### Clean deploys:\n"
        for d in clean[:5]:
            prompt += f"- {d.get('version', '?')} ({d.get('timestamp_str', '?')}) by {d.get('user', '?')}\n"
    prompt += "</historical_deployment_outcomes>\n\n\n"

    # <historical_code_changes_and_diffs>
    prompt += "<historical_code_changes_and_diffs>\n"
    has_patches = False
    for d in problem[:5]:
        p = d.get("code_patches", {})
        if not p or "error" in p:
            continue
        has_patches = True
        files = p.get("files", [])
        prompt += f"""
### {d.get('version', '?')} ({d.get('timestamp_str', '?')}) — {d.get('deployment_result', '?').upper()}
Tag: {p.get('tag', p.get('commit', '?'))}
Previous tag: {p.get('previous_tag', 'N/A')}
Commits: {p.get('total_commits', '?')}
Files: {len(files)}, Lines: +{p.get('lines_added', 0)} -{p.get('lines_removed', 0)}
"""
        if p.get("commit_messages"):
            for msg in p["commit_messages"][:5]:
                prompt += f"  - {msg}\n"
        prompt += "Files:\n"
        for f in files[:10]:
            prompt += f"  - {f['filename']} (+{f['additions']} -{f['deletions']})\n"
        chars = 0
        for f in files:
            patch = f.get("patch", "")
            if not patch:
                continue
            if chars + len(patch) > 4000:
                prompt += "[... truncated]\n"
                break
            prompt += f"```diff\n// {f['filename']}\n{patch}\n```\n"
            chars += len(patch)
    if not has_patches:
        prompt += "Historical code diffs not available.\n"
    prompt += "</historical_code_changes_and_diffs>\n\n\n"

    # Instructions
    versions = ", ".join(d.get("version", "?") for d in problem[:5])
    prompt += f"""Please process the provided information and generate a comprehensive assessment structured strictly around the following sections:

### 1. Current Deployment Analysis
Analyze `{dep.get('version', '?')}` across: Files Changed, Code Diff Size, Semantic/Contextual Analysis, Time of Deployment, Blast Radius.

### 2. Historical Failure Analysis
Analyze ({versions}) collectively. Identify systemic patterns, correlations, recurring alerts.

### 3. Dimension Comparison & Risk Matrix
| Dimension | Current Deployment Details | Historical Pattern Correlation | Risk Rating | Justification |
| :--- | :--- | :--- | :--- | :--- |
| **Files Changed** | | | | |
| **Diff Size** | | | | |
| **Semantic Risk** | | | | |
| **Deployment Time** | | | | |
| **Blast Radius** | | | | |

### 4. Red Flags & Final Recommendations
- **Risk-Prone Lines & Code Points**
- **Evidence-Based Flags (Pure History)**
- **Go/No-Go Recommendation** (Proceed / Postpone / Canary-with-Targeted-Tracing / Rollback-Strategy-Verification)
"""
    return prompt


# ══════════════════════════════════════════════════════════════════════════════
# STEP 7: CALL LLM
# ══════════════════════════════════════════════════════════════════════════════

async def call_llm(prompt: str) -> str:
    if not LLM_TOKEN:
        print("[Step 7] No LLM token set. Outputting prompt only.", file=sys.stderr)
        return ""

    headers = {
        "Authorization": f"Bearer {LLM_TOKEN}",
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
    }
    body = {
        "model": "claude-4-5-sonnet",
        "max_tokens": 4000,
        "messages": [{"role": "user", "content": prompt}],
    }
    print(f"[Step 7] Calling Claude via NerdCompletion...", file=sys.stderr)
    t0 = time.perf_counter()
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{LLM_URL}/v1/messages", headers=headers, json=body, timeout=90)
        resp.raise_for_status()
        data = resp.json()
        text = data["content"][0]["text"]
    print(f"[Step 7] Response in {time.perf_counter() - t0:.1f}s ({len(text)} chars)", file=sys.stderr)
    return text


# ══════════════════════════════════════════════════════════════════════════════
# MAIN PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

async def run_pipeline(entity_guid: str, timestamp_ms: int, account_id: int, target_index: int = 0):
    # Step 1+2: Fetch deployments
    deployments = await fetch_deployments(entity_guid, timestamp_ms, account_id)
    if not deployments:
        print("No deployments found.", file=sys.stderr)
        return

    # Step 3: Entity + relationships
    root_entity, related_map = await fetch_entity_and_related(entity_guid)

    # Step 4: Enrich with violations (parallel)
    deployments = await enrich_all_parallel(deployments, root_entity, related_map, account_id)

    # Step 5: Fetch code patches
    # Target deployment
    target_dep = deployments[target_index]
    await fetch_patches_for_deploy(target_dep, asyncio.Semaphore(1))

    # Historical violated deployments (parallel)
    violated = [d for d in deployments if len(d.get("root_entity_alert_violations", [])) > 0 and d != target_dep]
    if violated and GHE_TOKEN:
        await fetch_all_patches_parallel(violated)

    # Step 6: Build prompt
    prompt = build_prompt(target_dep, deployments)
    print(f"[Step 6] Prompt built: {len(prompt)} chars ({len(prompt)//4} ~tokens)", file=sys.stderr)

    # Step 7: Call LLM
    analysis = await call_llm(prompt)

    # Output
    if analysis:
        print(analysis)
    else:
        # If no LLM token, output the prompt itself
        print(prompt)


def main():
    global API_KEY, GHE_TOKEN, LLM_TOKEN, LLM_URL

    parser = argparse.ArgumentParser(description="DeploySense Risk Pipeline")
    parser.add_argument("--entity-guid", required=True)
    parser.add_argument("--account-id", type=int, required=True)
    parser.add_argument("--timestamp-ms", type=int, required=True, help="Epoch ms — analysis window ends here")
    parser.add_argument("--nr-api-key", default=os.environ.get("NR_API_KEY", ""))
    parser.add_argument("--ghe-token", default=os.environ.get("GHE_TOKEN", ""))
    parser.add_argument("--llm-token", default=os.environ.get("NERD_COMPLETION_TOKEN", ""))
    parser.add_argument("--llm-url", default="https://nerd-completion.staging-service.nr-ops.net")
    parser.add_argument("--target-index", type=int, default=0, help="Index of deployment to evaluate (0=most recent)")
    args = parser.parse_args()

    API_KEY = args.nr_api_key
    GHE_TOKEN = args.ghe_token
    LLM_TOKEN = args.llm_token
    LLM_URL = args.llm_url

    if not API_KEY:
        print("Error: --nr-api-key or NR_API_KEY required", file=sys.stderr)
        sys.exit(1)

    print(f"DeploySense Risk Pipeline", file=sys.stderr)
    print(f"  Entity: {args.entity_guid}", file=sys.stderr)
    print(f"  Account: {args.account_id}", file=sys.stderr)
    print(f"  GHE: {'Yes' if GHE_TOKEN else 'No'}", file=sys.stderr)
    print(f"  LLM: {'Yes' if LLM_TOKEN else 'No (prompt-only mode)'}", file=sys.stderr)
    print(f"", file=sys.stderr)

    asyncio.run(run_pipeline(args.entity_guid, args.timestamp_ms, args.account_id, args.target_index))


if __name__ == "__main__":
    main()
