"""Version-scoped OSV.dev advisory lookup for authenticated clients."""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated, Protocol, cast

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from security_review.api.errors import APIError
from security_review.intelligence.osv import OsvInputError, OsvQueryResult, OsvUnavailableError

router = APIRouter(prefix="/v1/vulnerabilities", tags=["vulnerabilities"])


class OsvQueryer(Protocol):
    def query_package(self, ecosystem: str, package: str, version: str) -> OsvQueryResult: ...


class PackageQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ecosystem: str = Field(min_length=1, max_length=40)
    package: str = Field(min_length=1, max_length=255)
    version: str = Field(min_length=1, max_length=100)


def get_osv_client(request: Request) -> OsvQueryer:
    return cast(OsvQueryer, request.app.state.osv_client)


@router.post("/query")
def query_vulnerabilities(
    query: PackageQuery,
    response: Response,
    client: Annotated[OsvQueryer, Depends(get_osv_client)],
) -> dict[str, object]:
    """Return OSV advisories and CVE identifiers for exactly one known version."""

    try:
        result = client.query_package(query.ecosystem, query.package, query.version)
    except OsvInputError as error:
        raise APIError(422, "invalid_package_query", "The package query is invalid.") from error
    except OsvUnavailableError as error:
        raise APIError(503, "osv_unavailable", "OSV vulnerability data is unavailable.") from error
    response.headers["Cache-Control"] = "no-store"
    return asdict(result)
