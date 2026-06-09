"""GitHub Action: Deploy Risk Scorer.

Runs inside a GitHub Actions workflow to:
1. Get diff stats for the current commit/PR
2. Query New Relic for historical deployment context
3. Calculate risk score
4. Output results for the action to post back to GitHub
"""

import json
import os
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime

# ─── Config from environment ──────────────────────────────────────────────────

NR_API_KEY = os.environ.get("NR_API_KEY", "")
NR_ACCOUNT_ID = int(os.environ.get("NR_ACCOUNT_ID", "0"))
NR_ENTITY_GUID = os.environ.get("NR_ENTITY_GUID", "")
NR_REGION = os.environ.get("NR_REGION", "US")
GHE_TOKEN = os.environ.get("GHE_TOKEN", "")
RISK_THRESHOLD = int(os.environ.get("RISK_THRESHOLD", "80"))
WARN_THRESHOLD = int(os.environ.get("WARN_THRESHOLD", "50"))

GITHUB_SHA = os.environ.get("GITHUB_SHA", "")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "")  # org/repo
GITHUB_BASE_REF = os.environ.get("GITHUB_BASE_REF", "")
GITHUB_HEAD_REF = os.environ.get("GITHUB_HEAD_REF", "")
GITHUB_OUTPUT = os.environ.get("GITHUB_OUTPUT", "")
GITHUB_STEP_SUMMARY = os.environ.get("GITHUB_STEP_SUMMARY", "")

# SSL context
try:
    import certifi
    SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    SSL_CTX = ssl.create_default_context()


def nerdgraph_query(query: str) -> dict:
    """Execute a NerdGraph query."""
    endpoint = ("https://api.newrelic.com/graphql" if NR_REGION == "US"
                else "https://api.eu.newrelic.com/graphql")
    payload = json.dumps({"query": query}).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json", "API-Key": NR_API_KEY},
    )
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"::warning::NerdGraph query failed: {e}")
        return {}


def github_api(path: str) -> dict:
    """Call GitHub API."""
    url = f"{os.environ.get('GITHUB_API_URL', 'https://api.github.com')}{path}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"token {GHE_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
        },
    )
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"::warning::GitHub API failed for {path}: {e}")
        return {}


# ─── Signal Gathering ─────────────────────────────────────────────────────────

def get_diff_stats() -> dict:
    """Get diff stats for the current PR or push."""
    stats = {"lines_added": 0, "lines_removed": 0, "files_changed": 0,
             "filenames": [], "commits": 0}

    if GITHUB_BASE_REF and GITHUB_HEAD_REF:
        compare = github_api(f"/repos/{GITHUB_REPO}/compare/{GITHUB_BASE_REF}...{GITHUB_HEAD_REF}")
        if compare:
            files = compare.get("files", [])
            stats["lines_added"] = sum(f.get("additions", 0) for f in files)
            stats["lines_removed"] = sum(f.get("deletions", 0) for f in files)
            stats["files_changed"] = len(files)
            stats["filenames"] = [f.get("filename", "") for f in files]
            stats["commits"] = len(compare.get("commits", []))
    elif GITHUB_SHA:
        commit = github_api(f"/repos/{GITHUB_REPO}/commits/{GITHUB_SHA}")
        if commit:
            s = commit.get("stats", {})
            stats["lines_added"] = s.get("additions", 0)
            stats["lines_removed"] = s.get("deletions", 0)
            files = commit.get("files", [])
            stats["files_changed"] = len(files)
            stats["filenames"] = [f.get("filename", "") for f in files]
            stats["commits"] = 1

    return stats


def get_nr_deploy_history() -> dict:
    """Get deployment history from NR Change Tracking."""
    if not NR_API_KEY or not NR_ACCOUNT_ID:
        return {"total_deploys": 0, "failures": 0, "failure_rate": 0}

    repo_name = GITHUB_REPO.split("/")[-1] if GITHUB_REPO else ""

    query = f"""{{
      actor {{
        account(id: {NR_ACCOUNT_ID}) {{
          total: nrql(query: "SELECT count(*) FROM ChangeTrackingEvent WHERE category = 'Deployment' AND deployment_phase = 'end' AND gheRepo = '{repo_name}' SINCE 90 days ago") {{
            results
          }}
          failures: nrql(query: "SELECT count(*) FROM ChangeTrackingEvent WHERE category = 'Deployment' AND deployment_phase = 'end' AND deployment_result = 'failure' AND gheRepo = '{repo_name}' SINCE 90 days ago") {{
            results
          }}
          recent_failures: nrql(query: "SELECT count(*) FROM ChangeTrackingEvent WHERE category = 'Deployment' AND deployment_phase = 'end' AND deployment_result = 'failure' AND gheRepo = '{repo_name}' SINCE 7 days ago") {{
            results
          }}
        }}
      }}
    }}"""

    data = nerdgraph_query(query)
    account = data.get("data", {}).get("actor", {}).get("account", {})

    total = 0
    failures = 0
    recent_failures = 0

    total_results = account.get("total", {}).get("results", [])
    if total_results:
        total = total_results[0].get("count", 0)

    fail_results = account.get("failures", {}).get("results", [])
    if fail_results:
        failures = fail_results[0].get("count", 0)

    recent_results = account.get("recent_failures", {}).get("results", [])
    if recent_results:
        recent_failures = recent_results[0].get("count", 0)

    return {
        "total_deploys": total,
        "failures": failures,
        "failure_rate": failures / max(total, 1),
        "recent_failures_7d": recent_failures,
    }


def get_nr_incidents() -> dict:
    """Get recent incident count from NR."""
    if not NR_API_KEY or not NR_ACCOUNT_ID or not NR_ENTITY_GUID:
        return {"critical": 0, "warning": 0}

    query = f"""{{
      actor {{
        account(id: {NR_ACCOUNT_ID}) {{
          nrql(query: "SELECT count(*) FROM NrAiIncident WHERE entity.guid = '{NR_ENTITY_GUID}' SINCE 7 days ago FACET priority") {{
            results
          }}
        }}
      }}
    }}"""

    data = nerdgraph_query(query)
    results = (data.get("data", {}).get("actor", {}).get("account", {})
               .get("nrql", {}).get("results", []))

    incidents = {"critical": 0, "warning": 0}
    for r in results:
        priority = (r.get("priority") or r.get("facet", "")).lower()
        count = r.get("count", 0)
        if "critical" in priority:
            incidents["critical"] = count
        elif "warning" in priority:
            incidents["warning"] = count

    return incidents


# ─── Risk Scoring ─────────────────────────────────────────────────────────────

def score_diff_size(stats: dict) -> tuple[int, str]:
    total = stats["lines_added"] + stats["lines_removed"]
    files = stats["files_changed"]
    if total < 50:
        return 3, f"{total} lines across {files} files (minimal)"
    elif total < 200:
        return 8, f"{total} lines across {files} files (moderate)"
    elif total < 500:
        return 14, f"{total} lines across {files} files (large)"
    else:
        return 20, f"{total} lines across {files} files (very large)"


def score_file_risk(filenames: list[str]) -> tuple[int, str]:
    points = 0
    risks = []
    lower = [f.lower() for f in filenames]

    if any("migration" in f or ".sql" in f for f in lower):
        points += 5
        risks.append("DB migration")
    if any("dockerfile" in f or "docker-compose" in f for f in lower):
        points += 3
        risks.append("Docker changes")
    if any(f in ("go.mod", "go.sum", "package.json", "requirements.txt") for f in lower):
        points += 3
        risks.append("dependency update")
    if any("config" in f or ".env" in f or ".yaml" in f for f in lower):
        points += 2
        risks.append("config changes")

    detail = ", ".join(risks) if risks else "no high-risk file patterns"
    return min(15, points), detail


def score_history(history: dict) -> tuple[int, str]:
    rate = history["failure_rate"]
    total = history["total_deploys"]
    failures = history["failures"]

    if total == 0:
        return 5, "No deploy history (first deploy)"
    elif rate < 0.05:
        return 3, f"{failures}/{total} failures ({rate:.0%}) — reliable repo"
    elif rate < 0.10:
        return 10, f"{failures}/{total} failures ({rate:.0%})"
    elif rate < 0.20:
        return 15, f"{failures}/{total} failures ({rate:.0%}) — elevated risk"
    else:
        return 20, f"{failures}/{total} failures ({rate:.0%}) — high failure rate"


def score_recent_incidents(incidents: dict) -> tuple[int, str]:
    critical = incidents["critical"]
    warning = incidents["warning"]
    points = min(15, critical * 8 + warning * 3)
    return points, f"{critical} critical, {warning} warning in last 7 days"


def score_timing() -> tuple[int, str]:
    now = datetime.utcnow()
    points = 0
    reasons = []
    if now.weekday() == 4:
        points += 5
        reasons.append("Friday deploy")
    elif now.weekday() >= 5:
        points += 7
        reasons.append("Weekend deploy")
    if now.hour < 6 or now.hour > 20:
        points += 5
        reasons.append("off-hours")
    return min(10, points), ", ".join(reasons) or "business hours"


def calculate_risk() -> dict:
    """Main risk calculation."""
    print("::group::Gathering signals")

    # 1. Diff stats from GitHub
    print("Fetching diff stats...")
    diff = get_diff_stats()
    print(f"  Lines: +{diff['lines_added']} -{diff['lines_removed']}, "
          f"Files: {diff['files_changed']}, Commits: {diff['commits']}")

    # 2. NR deploy history
    print("Querying New Relic deploy history...")
    history = get_nr_deploy_history()
    print(f"  {history['total_deploys']} deploys, {history['failures']} failures "
          f"({history['failure_rate']:.1%})")

    # 3. NR incidents
    print("Querying New Relic incidents...")
    incidents = get_nr_incidents()
    print(f"  {incidents['critical']} critical, {incidents['warning']} warning (7d)")

    print("::endgroup::")

    # Score each factor
    factors = []

    pts, detail = score_diff_size(diff)
    factors.append({"name": "Change Size", "points": pts, "detail": detail})

    pts, detail = score_file_risk(diff["filenames"])
    factors.append({"name": "File Risk", "points": pts, "detail": detail})

    pts, detail = score_history(history)
    factors.append({"name": "Historical Failure Rate", "points": pts, "detail": detail})

    pts, detail = score_recent_incidents(incidents)
    factors.append({"name": "Recent Incidents", "points": pts, "detail": detail})

    pts, detail = score_timing()
    factors.append({"name": "Deploy Timing", "points": pts, "detail": detail})

    total_score = min(100, sum(f["points"] for f in factors))

    if total_score <= 25:
        level = "LOW"
    elif total_score <= 50:
        level = "MEDIUM"
    elif total_score <= 75:
        level = "HIGH"
    else:
        level = "CRITICAL"

    # Recommendation
    if level == "LOW":
        rec = "Low risk. Proceed with standard monitoring."
    elif level == "MEDIUM":
        rec = "Moderate risk. Notify on-call and monitor for 15 min post-deploy."
    elif level == "HIGH":
        top = sorted(factors, key=lambda f: f["points"], reverse=True)[0]
        rec = f"High risk (top factor: {top['name']}). Deploy to canary first, have rollback ready."
    else:
        rec = "Critical risk. Require senior approval. Consider postponing."

    return {
        "score": total_score,
        "level": level,
        "factors": factors,
        "recommendation": rec,
        "diff": diff,
        "history": history,
    }


# ─── Output ───────────────────────────────────────────────────────────────────

def set_output(name: str, value: str):
    """Set GitHub Actions output."""
    if GITHUB_OUTPUT:
        with open(GITHUB_OUTPUT, "a") as f:
            f.write(f"{name}={value}\n")
    # Also print for local testing
    print(f"::set-output name={name}::{value}")


def write_summary(result: dict):
    """Write job summary (appears on the Actions run page)."""
    if not GITHUB_STEP_SUMMARY:
        return

    score = result["score"]
    level = result["level"]
    emoji = {"LOW": "✅", "MEDIUM": "⚠️", "HIGH": "🔶", "CRITICAL": "🚨"}[level]

    lines = [
        f"## {emoji} Deploy Risk Score: {score}/100 ({level})",
        "",
        "| Factor | Score | Detail |",
        "|--------|-------|--------|",
    ]
    for f in sorted(result["factors"], key=lambda x: -x["points"]):
        lines.append(f"| {f['name']} | +{f['points']} | {f['detail']} |")

    lines.extend([
        "",
        f"**Recommendation:** {result['recommendation']}",
        "",
        "---",
        f"*Repo: {GITHUB_REPO} | Commit: {GITHUB_SHA[:8]} | "
        f"NR Account: {NR_ACCOUNT_ID}*",
    ])

    with open(GITHUB_STEP_SUMMARY, "a") as f:
        f.write("\n".join(lines))


def main():
    print(f"Deploy Risk Scorer")
    print(f"  Repo: {GITHUB_REPO}")
    print(f"  Commit: {GITHUB_SHA[:12]}")
    print(f"  NR Account: {NR_ACCOUNT_ID}")
    print(f"  Thresholds: warn={WARN_THRESHOLD}, fail={RISK_THRESHOLD}")
    print()

    result = calculate_risk()

    # Set outputs
    set_output("risk-score", str(result["score"]))
    set_output("risk-level", result["level"])
    set_output("recommendation", result["recommendation"])

    # Build summary for status
    factor_summary = " | ".join(
        f"{f['name']}: +{f['points']}" for f in
        sorted(result["factors"], key=lambda x: -x["points"])[:3]
    )
    set_output("summary", factor_summary)

    # Write step summary
    write_summary(result)

    # Print results
    print(f"\n{'='*50}")
    print(f"RISK SCORE: {result['score']}/100 ({result['level']})")
    print(f"{'='*50}")
    for f in sorted(result["factors"], key=lambda x: -x["points"]):
        print(f"  +{f['points']:2d}  {f['name']}: {f['detail']}")
    print(f"\n{result['recommendation']}")

    # Exit code based on threshold
    if result["score"] >= RISK_THRESHOLD:
        print(f"\n::error::Risk score {result['score']} exceeds threshold {RISK_THRESHOLD}")
        sys.exit(1)
    elif result["score"] >= WARN_THRESHOLD:
        print(f"\n::warning::Risk score {result['score']} exceeds warn threshold {WARN_THRESHOLD}")


if __name__ == "__main__":
    main()
