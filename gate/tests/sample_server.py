"""Tiny synthetic MCP server used by tests and the M0 demo."""

from mcp.server.mcpserver import MCPServer

server = MCPServer("sample")


@server.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


@server.tool()
def echo(text: str) -> str:
    """Return the text unchanged."""
    return text


if __name__ == "__main__":
    server.run("stdio")
