from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any

app = FastAPI()


class Step(BaseModel):
    step_number: int
    tool: str
    args: dict[str, Any]
    tokens_used: int


class Request(BaseModel):
    budget_tokens: int
    steps: list[Step]


def normalize_string(s: str) -> str:
    return " ".join(s.split())


def canonicalize(obj):
    """
    Normalize arguments:
      - remove request_id
      - sort keys
      - normalize whitespace in strings
    """
    if isinstance(obj, dict):
        result = {}
        for k in sorted(obj.keys()):
            if k == "request_id":
                continue
            result[k] = canonicalize(obj[k])
        return result

    if isinstance(obj, list):
        return [canonicalize(x) for x in obj]

    if isinstance(obj, str):
        return normalize_string(obj)

    return obj


def same_call(a: Step, b: Step):
    return (
        a.tool == b.tool
        and canonicalize(a.args) == canonicalize(b.args)
    )


@app.post("/")
def guard(req: Request):

    total = sum(s.tokens_used for s in req.steps)

    if total >= req.budget_tokens:
        return {
            "decision": "halt",
            "reason": f"Cumulative tokens_used ({total}) has reached the budget ({req.budget_tokens})."
        }

    steps = req.steps

    #
    # Rule 1:
    # same tool + same canonical args
    # repeated >=3 consecutively
    #
    if len(steps) >= 3:

        count = 1

        for i in range(len(steps)-2, -1, -1):
            if same_call(steps[i], steps[i+1]):
                count += 1
            else:
                break

        if count >= 3:
            return {
                "decision": "halt",
                "reason": "Detected repeated identical tool calls."
            }

    #
    # Rule 2:
    # trailing A B A B A B
    #
    if len(steps) >= 6:

        tail = steps[-6:]

        A = tail[0]
        B = tail[1]

        ok = True

        for i in [2,4]:
            if not same_call(A, tail[i]):
                ok = False

        for i in [3,5]:
            if not same_call(B, tail[i]):
                ok = False

        if ok:
            return {
                "decision": "halt",
                "reason": "Detected repeating two-step cycle."
            }

    return {
        "decision": "continue",
        "reason": "Budget available and no loop detected."
    }
