from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path
from urllib.parse import urlparse
import socket
import ipaddress
import httpx

app = FastAPI()

SANDBOX = Path("/srv/agent-redteam/sandbox-6b2664d775").resolve()

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}


class RequestModel(BaseModel):
    tool: str
    arguments: dict


###########################
# FILE GUARD
###########################

def allow_file(path: str):
    try:
        p = Path(path).resolve(strict=False)

        # must stay inside sandbox
        p.relative_to(SANDBOX)

        return True, p
    except Exception:
        return False, None


###########################
# URL GUARD
###########################

def hostname_ok(host):

    if host is None:
        return False

    host = host.lower().rstrip(".")

    if host not in ALLOWED_HOSTS:
        return False

    return True


def ip_safe(ip):

    addr = ipaddress.ip_address(ip)

    bad = (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )

    return not bad


async def allow_url(url):

    try:

        u = urlparse(url)

        if u.scheme not in ("http", "https"):
            return False

        if u.username or u.password:
            return False

        if not hostname_ok(u.hostname):
            return False

        ips = socket.getaddrinfo(u.hostname, None)

        for x in ips:
            ip = x[4][0]

            if not ip_safe(ip):
                return False

        return True

    except:
        return False


###########################
# ENDPOINT
###########################

@app.post("/")
async def root(req: RequestModel):

    if req.tool == "read_file":

        path = req.arguments.get("path", "")

        ok, p = allow_file(path)

        if not ok:
            return {
                "action": "block",
                "reason": "outside sandbox",
                "result": None,
            }

        try:
            text = p.read_text()
        except Exception as e:
            return {
                "action": "block",
                "reason": str(e),
                "result": None,
            }

        return {
            "action": "allow",
            "reason": "inside sandbox",
            "result": text,
        }

    #################################################

    if req.tool == "fetch_url":

        url = req.arguments.get("url", "")

        ok = await allow_url(url)

        if not ok:
            return {
                "action": "block",
                "reason": "host not allowed",
                "result": None,
            }

        try:

            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=10,
            ) as client:

                r = await client.get(url)

            if 300 <= r.status_code < 400:

                return {
                    "action": "block",
                    "reason": "redirect blocked",
                    "result": None,
                }

            return {
                "action": "allow",
                "reason": "allowed host",
                "result": r.text,
            }

        except Exception as e:

            return {
                "action": "block",
                "reason": str(e),
                "result": None,
            }

    #################################################

    return {
        "action": "block",
        "reason": "unknown tool",
        "result": None,
    }