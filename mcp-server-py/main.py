"""
Shannon MCP Server — Python (FastMCP)

Exposes Shannon's autonomous pentesting capabilities as MCP tools.
Built with FastMCP following the mcp_skill guide.

Tools:
    - start_scan      : Kick-off a new pentest workflow via Temporal.
    - get_scan_status  : Query a running/completed workflow for progress.
    - get_scan_report  : Retrieve the final security assessment report.
    - list_sample_reports : List available sample reports shipped with Shannon.
    - read_sample_report  : Read the contents of a sample report.

Usage:
    # Development / Inspector
    uv run fastmcp dev main.py

    # Stdio transport (for Claude Desktop / Gemini)
    uv run fastmcp run main.py
"""

from fastmcp import FastMCP
from pathlib import Path
import os
import glob
import json
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
#  Server instance
# ---------------------------------------------------------------------------
mcp = FastMCP(name="shannon-pentest")

# Project root (shannon/) — one level up from mcp-server-py/
# In cloud deployment, this might be the current directory if using a subfolder
_SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = _SCRIPT_DIR.parent

# Fallback in case we are running in a flat structure on a platform
if not (PROJECT_ROOT / "repos").exists() and _SCRIPT_DIR.name == "mcp-server-py":
    # If the parent doesn't have repos, but we are in subfolder, stay here or check local
    if (_SCRIPT_DIR / "repos").exists():
        PROJECT_ROOT = _SCRIPT_DIR


# ---------------------------------------------------------------------------
#  Tool 1: start_scan
# ---------------------------------------------------------------------------
@mcp.tool()
async def start_scan(
    url: str,
    repo_name: str,
    config_path: str = "",
    output_path: str = "",
    workflow_id: str = "",
) -> str:
    """Start a Shannon pentest scan against a target web application.

    This connects to the Temporal server and triggers the full autonomous
    pentesting pipeline (Recon → Vuln Analysis → Exploitation → Reporting).

    Args:
        url: Target URL to pentest (e.g. https://example.com).
        repo_name: Folder name under ./repos/ containing the target source code.
        config_path: Optional YAML config file path inside ./configs/.
        output_path: Optional custom output directory for reports.
        workflow_id: Optional custom workflow ID. Auto-generated if empty.

    Returns:
        A summary with the workflow ID and monitoring instructions.
    """
    try:
        from temporal_client import get_temporal_client, start_workflow

        # Validate repo exists
        repo_dir = PROJECT_ROOT / "repos" / repo_name
        if not repo_dir.exists():
            return (
                f"❌ Error: Repository not found at {repo_dir}\n\n"
                f"Please place your target repository under ./repos/{repo_name}\n"
                f"Example: git clone <repo-url> ./repos/{repo_name}"
            )

        # Container path for the repo (matches docker-compose volume mount)
        container_repo = f"/repos/{repo_name}"

        # Resolve config path
        resolved_config = ""
        if config_path:
            config_file = PROJECT_ROOT / "configs" / config_path
            if not config_file.exists():
                return f"❌ Error: Config file not found at {config_file}"
            resolved_config = config_path

        client = await get_temporal_client()
        wf_id = await start_workflow(
            client=client,
            web_url=url,
            repo_path=container_repo,
            config_path=resolved_config,
            output_path=output_path,
            workflow_id=workflow_id,
        )

        return (
            f"✅ Shannon pentest started successfully!\n\n"
            f"  Workflow ID : {wf_id}\n"
            f"  Target      : {url}\n"
            f"  Repository  : {repo_name}\n"
            f"  Config      : {config_path or '(none)'}\n\n"
            f"📊 Monitor progress:\n"
            f"  • Web UI : http://localhost:8233\n"
            f"  • CLI    : ./shannon query ID={wf_id}\n"
            f"  • Logs   : ./shannon logs  ID={wf_id}\n\n"
            f"💡 Use get_scan_status(workflow_id='{wf_id}') to check progress."
        )

    except Exception as e:
        return f"❌ Failed to start scan: {str(e)}\n\nMake sure Docker containers are running (./shannon start ...)"


# ---------------------------------------------------------------------------
#  Tool 2: get_scan_status
# ---------------------------------------------------------------------------
@mcp.tool()
async def get_scan_status(workflow_id: str) -> str:
    """Query the progress of a running or completed Shannon pentest scan.

    Returns the current phase, active agent, completed agents, metrics, and
    any errors encountered during the scan.

    Args:
        workflow_id: The workflow ID returned by start_scan.

    Returns:
        Formatted status report with progress details.
    """
    try:
        from temporal_client import get_temporal_client, query_workflow_progress

        client = await get_temporal_client()
        progress = await query_workflow_progress(client, workflow_id)

        # Format duration helper
        def fmt_duration(ms):
            if ms is None:
                return "N/A"
            seconds = int(ms / 1000)
            minutes = seconds // 60
            hours = minutes // 60
            if hours > 0:
                return f"{hours}h {minutes % 60}m"
            elif minutes > 0:
                return f"{minutes}m {seconds % 60}s"
            return f"{seconds}s"

        status = progress.get("status", "unknown")
        status_emoji = {"running": "🔄", "completed": "✅", "failed": "❌"}.get(status, "❓")

        result = (
            f"{status_emoji} Workflow: {workflow_id}\n"
            f"{'─' * 50}\n"
            f"  Status        : {status.upper()}\n"
            f"  Current Phase : {progress.get('currentPhase') or 'none'}\n"
            f"  Current Agent : {progress.get('currentAgent') or 'none'}\n"
            f"  Elapsed       : {fmt_duration(progress.get('elapsedMs'))}\n"
        )

        completed = progress.get("completedAgents", [])
        result += f"  Completed     : {len(completed)}/13 agents\n"

        if completed:
            result += f"\n📋 Completed Agents:\n"
            metrics = progress.get("agentMetrics", {})
            for agent in completed:
                m = metrics.get(agent, {})
                dur = fmt_duration(m.get("durationMs"))
                cost = f"${m['costUsd']:.4f}" if m.get("costUsd") else ""
                model = f" [{m['model']}]" if m.get("model") else ""
                result += f"  ✓ {agent}{model} ({dur}{', ' + cost if cost else ''})\n"

        error = progress.get("error")
        if error:
            failed_agent = progress.get("failedAgent", "unknown")
            result += f"\n⚠️ Error in agent '{failed_agent}':\n  {error}\n"

        return result

    except Exception as e:
        error_msg = str(e)
        if "not found" in error_msg.lower():
            return f"❌ Workflow not found: {workflow_id}\n\nCheck the workflow ID and try again."
        return f"❌ Failed to query workflow: {error_msg}\n\nMake sure Docker containers are running."


# ---------------------------------------------------------------------------
#  Tool 3: get_scan_report
# ---------------------------------------------------------------------------
@mcp.tool()
async def get_scan_report(workflow_id: str) -> str:
    """Retrieve the final security assessment report for a completed scan.

    Reads the comprehensive report markdown file from the audit-logs directory.

    Args:
        workflow_id: The workflow ID of a completed scan.

    Returns:
        The full markdown content of the security report, or an error if not found.
    """
    try:
        # Search in audit-logs for the workflow directory
        audit_dir = PROJECT_ROOT / "audit-logs"
        if not audit_dir.exists():
            return "❌ No audit-logs directory found. Has any scan been run?"

        # Try to find the report — could be in deliverables/ subfolder
        possible_paths = [
            audit_dir / workflow_id / "deliverables" / "comprehensive_security_assessment_report.md",
            audit_dir / workflow_id / "comprehensive_security_assessment_report.md",
        ]

        # Also search by glob in case the directory naming varies
        glob_pattern = str(audit_dir / f"*{workflow_id}*" / "deliverables" / "*.md")
        glob_matches = glob.glob(glob_pattern)

        for p in possible_paths:
            if p.exists():
                content = p.read_text(encoding="utf-8")
                return (
                    f"📄 Security Report for: {workflow_id}\n"
                    f"{'═' * 60}\n\n"
                    f"{content}"
                )

        if glob_matches:
            content = Path(glob_matches[0]).read_text(encoding="utf-8")
            return (
                f"📄 Security Report for: {workflow_id}\n"
                f"{'═' * 60}\n\n"
                f"{content}"
            )

        # List what we do have
        available = []
        if audit_dir.exists():
            available = [d.name for d in audit_dir.iterdir() if d.is_dir()]

        msg = f"❌ Report not found for workflow: {workflow_id}\n\n"
        if available:
            msg += "Available audit-log directories:\n"
            for d in available[:10]:
                msg += f"  • {d}\n"
        else:
            msg += "No completed scans found in audit-logs/\n"

        return msg

    except Exception as e:
        return f"❌ Error reading report: {str(e)}"


# ---------------------------------------------------------------------------
#  Tool 4: list_sample_reports
# ---------------------------------------------------------------------------
@mcp.tool()
def list_sample_reports() -> str:
    """List the sample pentest reports shipped with Shannon.

    These demonstrate Shannon's output quality against well-known
    vulnerable applications (OWASP Juice Shop, crAPI, c{api}tal).

    Returns:
        A list of available sample reports with descriptions.
    """
    reports_dir = PROJECT_ROOT / "sample-reports"
    if not reports_dir.exists():
        return "❌ sample-reports directory not found."

    reports = list(reports_dir.glob("*.md"))
    if not reports:
        return "No sample reports found."

    result = "📊 Available Sample Reports:\n" + "─" * 40 + "\n\n"

    descriptions = {
        "shannon-report-juice-shop.md": "OWASP Juice Shop — 20+ critical vulnerabilities including auth bypass and DB exfiltration",
        "shannon-report-capital-api.md": "Checkmarx c{api}tal API — 15 critical/high vulns, full application compromise",
        "shannon-report-crapi.md": "OWASP crAPI — 15+ critical vulns, JWT attacks, SSRF, DB compromise",
    }

    for report in sorted(reports):
        desc = descriptions.get(report.name, "Security assessment report")
        size_kb = report.stat().st_size / 1024
        result += f"  📄 {report.name} ({size_kb:.1f} KB)\n"
        result += f"     {desc}\n\n"

    result += "💡 Use read_sample_report(filename='...') to view a report."
    return result


# ---------------------------------------------------------------------------
#  Tool 5: read_sample_report
# ---------------------------------------------------------------------------
@mcp.tool()
def read_sample_report(filename: str) -> str:
    """Read the contents of a sample pentest report.

    Args:
        filename: Name of the report file (e.g. 'shannon-report-juice-shop.md').

    Returns:
        The full markdown content of the sample report.
    """
    reports_dir = PROJECT_ROOT / "sample-reports"
    report_path = reports_dir / filename

    if not report_path.exists():
        available = [f.name for f in reports_dir.glob("*.md")]
        return (
            f"❌ Report not found: {filename}\n\n"
            f"Available reports: {', '.join(available)}"
        )

    content = report_path.read_text(encoding="utf-8")
    return (
        f"📄 Sample Report: {filename}\n"
        f"{'═' * 60}\n\n"
        f"{content}"
    )


# ---------------------------------------------------------------------------
#  Tool 6: list_configs
# ---------------------------------------------------------------------------
@mcp.tool()
def list_configs() -> str:
    """List available configuration files for Shannon scans.

    Configuration files control authentication, rules (avoid/focus areas),
    and other scan parameters.

    Returns:
        A list of YAML config files in the configs/ directory.
    """
    configs_dir = PROJECT_ROOT / "configs"
    if not configs_dir.exists():
        return "❌ configs/ directory not found."

    configs = list(configs_dir.glob("*.yaml")) + list(configs_dir.glob("*.yml"))
    if not configs:
        return "No configuration files found."

    result = "⚙️ Available Configurations:\n" + "─" * 40 + "\n\n"
    for cfg in sorted(configs):
        size_kb = cfg.stat().st_size / 1024
        result += f"  📝 {cfg.name} ({size_kb:.1f} KB)\n"

    result += (
        "\n💡 Use a config when starting a scan:\n"
        "   start_scan(url='...', repo_name='...', config_path='my-config.yaml')"
    )
    return result


# ---------------------------------------------------------------------------
#  Tool 7: list_repos
# ---------------------------------------------------------------------------
@mcp.tool()
def list_repos() -> str:
    """List repositories available for scanning in the repos/ directory.

    Shannon expects target source code to be placed under ./repos/.

    Returns:
        A list of directories under repos/.
    """
    repos_dir = PROJECT_ROOT / "repos"
    if not repos_dir.exists():
        return (
            "❌ repos/ directory not found.\n\n"
            "Create it and clone your target repo:\n"
            "  mkdir repos && git clone <url> repos/<name>"
        )

    repos = [d for d in repos_dir.iterdir() if d.is_dir()]
    if not repos:
        return (
            "No repositories found in repos/.\n\n"
            "Clone your target repo:\n"
            "  git clone <url> repos/<name>"
        )

    result = "📂 Available Repositories:\n" + "─" * 40 + "\n\n"
    for repo in sorted(repos):
        # Count files for a rough size indicator
        file_count = sum(1 for _ in repo.rglob("*") if _.is_file())
        result += f"  📁 {repo.name} ({file_count} files)\n"

    result += (
        "\n💡 Start a scan with:\n"
        "   start_scan(url='https://your-app.com', repo_name='<name>')"
    )
    return result


# ---------------------------------------------------------------------------
#  Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run()
