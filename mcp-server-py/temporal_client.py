"""
Temporal Client Helper for Shannon MCP Server.

Encapsulates all Temporal workflow interaction logic:
  - Connecting to the Temporal server
  - Starting pentest workflows
  - Querying workflow progress
"""

import os
from temporalio.client import Client


# Default Temporal address (matches docker-compose.yml)
DEFAULT_TEMPORAL_ADDRESS = "localhost:7233"

# Workflow constants (must match shannon/src/temporal/shared.ts)
TASK_QUEUE = "shannon-pipeline"
WORKFLOW_NAME = "pentestPipelineWorkflow"
PROGRESS_QUERY = "getProgress"


async def get_temporal_client() -> Client:
    """
    Connect to the Temporal server.

    Uses TEMPORAL_ADDRESS env var, falling back to localhost:7233.
    """
    address = os.getenv("TEMPORAL_ADDRESS", DEFAULT_TEMPORAL_ADDRESS)
    client = await Client.connect(address)
    return client


async def start_workflow(
    client: Client,
    web_url: str,
    repo_path: str,
    config_path: str = "",
    output_path: str = "",
    workflow_id: str = "",
) -> str:
    """
    Start a Shannon pentest pipeline workflow.

    Args:
        client: Connected Temporal client.
        web_url: Target URL to pentest (e.g. https://example.com).
        repo_path: Path to the repo inside the container (e.g. /repos/my-app).
        config_path: Optional path to a YAML config file.
        output_path: Optional output directory for reports.
        workflow_id: Optional custom workflow ID.

    Returns:
        The workflow ID of the started workflow.
    """
    import time

    # Build input matching PipelineInput from shared.ts
    pipeline_input = {
        "webUrl": web_url,
        "repoPath": repo_path,
    }
    if config_path:
        pipeline_input["configPath"] = config_path
    if output_path:
        pipeline_input["outputPath"] = output_path

    # Generate workflow ID if not provided
    if not workflow_id:
        # Sanitize hostname for workflow ID (matches sanitizeHostname in audit/utils.ts)
        from urllib.parse import urlparse
        parsed = urlparse(web_url)
        hostname = parsed.hostname or "unknown"
        hostname = hostname.replace(".", "_")
        workflow_id = f"{hostname}_shannon-{int(time.time() * 1000)}"

    handle = await client.start_workflow(
        WORKFLOW_NAME,
        pipeline_input,
        id=workflow_id,
        task_queue=TASK_QUEUE,
    )

    return handle.id


async def query_workflow_progress(client: Client, workflow_id: str) -> dict:
    """
    Query a running/completed Shannon workflow for its progress.

    Args:
        client: Connected Temporal client.
        workflow_id: The workflow ID to query.

    Returns:
        A dict with workflow progress data matching PipelineProgress:
        {
            "status": "running" | "completed" | "failed",
            "currentPhase": str | None,
            "currentAgent": str | None,
            "completedAgents": [str],
            "failedAgent": str | None,
            "error": str | None,
            "startTime": int,
            "agentMetrics": { agent_name: { durationMs, inputTokens, ... } },
            "workflowId": str,
            "elapsedMs": int,
        }
    """
    handle = client.get_workflow_handle(workflow_id)
    progress = await handle.query(PROGRESS_QUERY)
    return progress
