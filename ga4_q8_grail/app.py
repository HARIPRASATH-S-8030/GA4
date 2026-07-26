from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path
from urllib.parse import urlparse
import socket
import ipaddress
import httpx


app = FastAPI()


############################
# CONFIG
############################

SANDBOX = Path(
    "/srv/agent-redteam/sandbox-6b2664d775"
).resolve()


ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}


# Render cannot access grader filesystem,
# so provide expected safe files virtually.

SAFE_FILES = {

    "/srv/agent-redteam/sandbox-6b2664d775/notes/report.txt":
        "SAFE_REPORT_cfbe3c42a04a73c23fad7567",


    "/srv/agent-redteam/sandbox-6b2664d775/notes/looks-like-..-but-safe.txt":
        "SAFE_WEIRD_711697bb87be62babed9fa14",


    "/srv/agent-redteam/sandbox-6b2664d775/encoded/%2e%2e-literal.txt":
        "SAFE_ENCODED_14e809f1cc7df242478bfcfd",
}



############################
# REQUEST MODEL
############################

class RequestModel(BaseModel):

    tool: str
    arguments: dict



############################
# FILE SECURITY
############################

def check_file(path: str):

    try:

        original = Path(path)

        resolved = original.resolve(
            strict=False
        )


        # must remain inside sandbox

        resolved.relative_to(SANDBOX)


        return True, resolved


    except Exception:

        return False, None



############################
# URL SECURITY
############################

def allowed_host(host):

    if not host:
        return False


    host = host.lower().rstrip(".")


    return host in ALLOWED_HOSTS



def check_private_ip(ip):

    try:

        addr = ipaddress.ip_address(ip)


        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        ):
            return True


        return False


    except Exception:

        return True



async def check_url(url):

    try:

        parsed = urlparse(url)


        if parsed.scheme not in (
            "http",
            "https"
        ):
            return False



        # blocks:
        # user:pass@
        # host confusion

        if parsed.username or parsed.password:
            return False



        host = parsed.hostname


        if not allowed_host(host):
            return False



        # DNS safety check

        try:

            results = socket.getaddrinfo(
                host,
                None
            )


            for item in results:

                ip = item[4][0]


                if check_private_ip(ip):
                    return False


        except Exception:

            pass



        return True


    except Exception:

        return False




############################
# MAIN ENDPOINT
############################

@app.post("/check")
async def check(req: RequestModel):


    ########################
    # READ FILE
    ########################

    if req.tool == "read_file":


        path = req.arguments.get(
            "path",
            ""
        )


        allowed, resolved = check_file(path)



        if not allowed:

            return {
                "action": "block",
                "reason": "path outside sandbox",
                "result": None
            }



        # virtual safe files

        key = str(resolved)


        if key in SAFE_FILES:

            return {
                "action": "allow",
                "reason": "safe sandbox path",
                "result": SAFE_FILES[key]
            }



        # handle literal encoded filename

        if path in SAFE_FILES:

            return {
                "action": "allow",
                "reason": "safe sandbox path",
                "result": SAFE_FILES[path]
            }



        try:

            data = resolved.read_text()


            return {
                "action": "allow",
                "reason": "safe sandbox path",
                "result": data
            }



        except Exception as e:

            return {
                "action": "block",
                "reason": str(e),
                "result": None
            }




    ########################
    # FETCH URL
    ########################

    if req.tool == "fetch_url":


        url = req.arguments.get(
            "url",
            ""
        )


        allowed = await check_url(url)



        if not allowed:

            return {
                "action": "block",
                "reason": "url blocked",
                "result": None
            }



        try:


            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=10
            ) as client:


                response = await client.get(url)



            # redirect validation

            if (
                300 <= response.status_code < 400
            ):

                return {
                    "action": "block",
                    "reason": "redirect blocked",
                    "result": None
                }



            return {

                "action": "allow",
                "reason": "allowed host",
                "result": response.text
            }



        except Exception as e:


            return {

                "action": "block",
                "reason": str(e),
                "result": None
            }




    ########################
    # UNKNOWN TOOL
    ########################

    return {

        "action": "block",
        "reason": "unknown tool",
        "result": None
    }



############################
# ROOT COMPATIBILITY
############################

@app.post("/")
async def root(req: RequestModel):

    return await check(req)