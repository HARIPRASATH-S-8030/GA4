from hashlib import sha256

from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers

EMAIL = "24f1001287@ds.study.iitm.ac.in".strip().lower()

mcp = FastMCP("GA4 MCP Server")


@mcp.tool(
    name="solve_challenge",
    description="Returns the exam challenge response."
)
def solve_challenge() -> str:
    """
    Reads the challenge from the X-Exam-Challenge HTTP header and returns
    the first 16 lowercase hexadecimal characters of:

        SHA256("<challenge>:<normalized_email>")
    """

    headers = get_http_headers()

    challenge = headers.get("x-exam-challenge")

    if challenge is None:
        raise ValueError("Missing X-Exam-Challenge header")

    return sha256(
        f"{challenge}:{EMAIL}".encode("utf-8")
    ).hexdigest()[:16]


app = mcp.http_app(path="/mcp")