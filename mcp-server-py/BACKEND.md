# Shannon MCP Server (Python) — Backend Documentation

## Overview

Python-based MCP server built with **FastMCP** that exposes Shannon's autonomous pentesting capabilities as tools. Allows LLMs (Claude Desktop, Gemini, etc.) to control Shannon scans via natural language.

## Tech Stack

- **FastMCP** — MCP server framework (decorator-based)
- **temporalio** — Python Temporal client for workflow orchestration
- **python-dotenv** — Environment variable management
- **uv** — Fast Python package manager

## Architecture

```
mcp-server-py/
├── main.py              # MCP server entry point (all tools defined here)
├── temporal_client.py   # Temporal connection & workflow interaction helper
├── pyproject.toml       # Project config + dependencies
└── .python-version      # Python version pin
```

The server communicates with Shannon's Temporal-based workflow engine. Shannon itself runs inside Docker containers (see `docker-compose.yml` in project root).

```
  LLM (Claude/Gemini)
      │
      ▼
  MCP Server (this)  ───stdio───▶  FastMCP
      │
      ▼
  Temporal Client  ───gRPC───▶  Temporal Server (Docker :7233)
      │
      ▼
  Shannon Worker (Docker)  ───▶  Pentest Pipeline
```

## Tools Exposed

| Tool | Description | Requires Temporal |
|------|-------------|:-:|
| `start_scan` | Start a new pentest workflow | ✅ |
| `get_scan_status` | Query workflow progress | ✅ |
| `get_scan_report` | Retrieve final security report | ❌ (reads files) |
| `list_sample_reports` | List bundled sample reports | ❌ |
| `read_sample_report` | Read a sample report's content | ❌ |
| `list_configs` | List available YAML configs | ❌ |
| `list_repos` | List repos available for scanning | ❌ |

## Setup

```bash
cd shannon/mcp-server-py

# Install dependencies
uv sync

# Development mode (MCP Inspector)
uv run fastmcp dev main.py

# Production mode (stdio transport)
uv run fastmcp run main.py
```

## Claude Desktop Integration

```bash
uv run fastmcp install claude-desktop main.py
```

Or manually edit Claude Desktop config:

```json
{
  "mcpServers": {
    "shannon-pentest": {
      "command": "C:/path/to/uv.exe",
      "args": ["run", "fastmcp", "run", "main.py"],
      "cwd": "C:/path/to/shannon/mcp-server-py"
    }
  }
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TEMPORAL_ADDRESS` | `localhost:7233` | Temporal server gRPC address |

## Prerequisites

- Shannon Docker containers must be running for `start_scan` and `get_scan_status`
- Target repos must be placed under `shannon/repos/<name>/`
- Config files go in `shannon/configs/`

## Usage Examples (Natural Language)

- "List the available repos for scanning"
- "Start a pentest scan on https://example.com using repo my-app"
- "Check the status of workflow shannon-1234567890"
- "Show me the final report for the last scan"
- "List the sample reports and show me the Juice Shop one"
