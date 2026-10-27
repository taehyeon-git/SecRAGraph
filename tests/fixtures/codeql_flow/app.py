"""FastAPI entry points for an isolated CodeQL path-query check."""

from fastapi import FastAPI

from codeql_flow.flow import allowlisted, forward

app = FastAPI()


@app.get("/raw/{value}")
def raw_route(value: str) -> str:
    return forward(value)


@app.get("/checked/{value}")
def checked_route(value: str) -> str:
    return forward(allowlisted(value))
