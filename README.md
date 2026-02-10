# Shannon MCP Server

Autonomous pentesting tools exposed via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `start_scan` | Start a pentest workflow via Temporal |
| `get_scan_status` | Query progress of a running/completed scan |
| `get_scan_report` | Retrieve the final security report |
| `list_sample_reports` | List sample reports shipped with Shannon |
| `read_sample_report` | Read contents of a sample report |
| `list_configs` | List available scan configuration files |
| `list_repos` | List repositories available for scanning |

## Entrypoint

```
main.py:mcp
```

## Local Development

```bash
pip install -e .
python main.py
```
