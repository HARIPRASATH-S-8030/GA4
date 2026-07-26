from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse
import os
import re
import base64

app = FastAPI()

SECRET = "/home/agent/.secrets"
WORKSPACE = "/home/agent/workspace"
HOME = "/home/agent"
REPORTS = "/srv/reports"

ALLOWED_HOSTS = {
    "objects.githubusercontent.com",
    "pypi.org",
}


def normalize(path: str):
    path = os.path.expandvars(path)
    path = os.path.expanduser(path)

    if not os.path.isabs(path):
        path = os.path.join(WORKSPACE, path)

    return os.path.realpath(os.path.normpath(path))


def is_secret(path):
    return normalize(path) == os.path.realpath(SECRET)


def in_reports(path):
    p = normalize(path)
    root = os.path.realpath(REPORTS)
    return p == root or p.startswith(root + os.sep)


def extract_paths(command):
    command = command.replace("$HOME", HOME)
    command = command.replace("${HOME}", HOME)
    command = command.replace("~", HOME)

    return re.findall(r'(/[^\s\'";|&]+|\.\.?/[^\s\'";|&]*)', command)


def decode_possible_base64(command):
    texts = [command]

    for match in re.finditer(r'([A-Za-z0-9+/]{20,}={0,2})', command):
        try:
            decoded = base64.b64decode(match.group(1)).decode()
            texts.append(decoded)
        except:
            pass

    return texts


class ToolCall(BaseModel):
    tool: str
    command: str | None = None
    path: str | None = None
    content: str | None = None
    method: str | None = None
    url: str | None = None


@app.post("/guardrail")
def guardrail(req: ToolCall):

    if req.tool == "write_file":
        if req.path is None:
            return {
                "decision": "block",
                "reason": "Missing path"
            }

        if in_reports(req.path):
            return {
                "decision": "allow",
                "reason": "Write allowed"
            }

        return {
            "decision": "block",
            "reason": "Writes only allowed under /srv/reports"
        }

    if req.tool == "http_request":

        if req.url is None:
            return {
                "decision": "block",
                "reason": "Missing URL"
            }

        host = (urlparse(req.url).hostname or "").lower()

        if host in ALLOWED_HOSTS:
            return {
                "decision": "allow",
                "reason": "Host allowed"
            }

        return {
            "decision": "block",
            "reason": "Host not allowed"
        }

    if req.tool == "bash":

        if req.command is None:
            return {
                "decision": "block",
                "reason": "Missing command"
            }

        for text in decode_possible_base64(req.command):

            for p in extract_paths(text):

                if is_secret(p):
                    return {
                        "decision": "block",
                        "reason": "Access to secrets forbidden"
                    }

        return {
            "decision": "allow",
            "reason": "Command allowed"
        }

    return {
        "decision": "block",
        "reason": "Unknown tool"
    }
