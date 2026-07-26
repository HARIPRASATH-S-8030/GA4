from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any
import re

app = FastAPI()


class Step(BaseModel):
    step_number: int
    tool: str
    args: dict[str, Any]
    tokens_used: int


class Request(BaseModel):
    budget_tokens: int
    steps: list[Step]


# -----------------------------
# Canonicalization
# -----------------------------

_whitespace = re.compile(r"\s+")


def canonicalize(value):
    """
    Canonicalize arguments by:
      - removing request_id keys
      - sorting dictionary keys
      - recursively processing nested dict/list
      - collapsing whitespace inside strings
    """

    if isinstance(value, dict):
        return {
            k: canonicalize(value[k])
            for k in sorted(value)
            if k != "request_id"
        }

    if isinstance(value, list):
        return [canonicalize(v) for v in value]

    if isinstance(value, str):
        return _whitespace.sub(" ", value).strip()

    return value


def same_call(a: Step, b: Step):
    return (
        a.tool == b.tool
        and canonicalize(a.args) == canonicalize(b.args)
    )


# -----------------------------
# Loop detectors
# -----------------------------

def repeated_identical_calls(steps):
    """
    Detect 3+ identical consecutive calls at end.
    """

    if len(steps) < 3:
        return False

    count = 1

    for i in range(len(steps) - 2, -1, -1):
        if same_call(steps[i], steps[i + 1]):
            count += 1
        else:
            break

    return count >= 3


def repeated_two_cycle(steps):
    """
    Detect trailing

    A B A B A B

    or longer.

    Must have at least 6 trailing steps.
    """

    n = len(steps)

    if n < 6:
        return False

    A = steps[-2]
    B = steps[-1]

    length = 2

    i = n - 3

    expect = A

    while i >= 0:

        if same_call(steps[i], expect):

            length += 1

            expect = B if expect is A else A

            i -= 1

        else:
            break

    return length >= 6


# -----------------------------
# Endpoint
# -----------------------------

@app.post("/")
def run_guard(req: Request):

    total = sum(step.tokens_used for step in req.steps)

    if total >= req.budget_tokens:
        return {
            "decision": "halt",
            "reason": f"Cumulative tokens_used ({total}) has reached the budget ({req.budget_tokens}).",
        }

    if repeated_identical_calls(req.steps):
        return {
            "decision": "halt",
            "reason": "Detected repeated identical tool calls.",
        }

    if repeated_two_cycle(req.steps):
        return {
            "decision": "halt",
            "reason": "Detected repeating two-step cycle.",
        }

    return {
        "decision": "continue",
        "reason": "Budget available and no loop detected.",
    }