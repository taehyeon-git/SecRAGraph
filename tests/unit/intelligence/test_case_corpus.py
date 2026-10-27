"""Case-selected MITRE evidence is bounded, attributable, and usable offline."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import httpx
import pytest

from security_review.intelligence import case_corpus
from security_review.intelligence.manifest import load_verified_corpus

REPO_ROOT = Path(__file__).resolve().parents[3]
EXPECTED_IDS = [
    "CWE-78",
    "CWE-89",
    "CWE-95",
    "CWE-200",
    "CWE-295",
    "CWE-347",
    "CWE-502",
    "CWE-798",
]


@pytest.fixture
def corpus_cache(tmp_path_factory: pytest.TempPathFactory) -> Path:
    # Keep Windows worktree + pytest + immutable snapshot paths below MAX_PATH.
    return tmp_path_factory.mktemp("c")


def _json_response(payload: object) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=httpx.ByteStream(json.dumps(payload).encode("utf-8")),
    )


def _mitre_response(
    request: httpx.Request, requests: list[str], *, wrong_id: bool = False
) -> httpx.Response:
    requests.append(str(request.url))
    assert request.url.scheme == "https"
    assert request.url.host == "cwe-api.mitre.org"
    if request.url.path == "/api/v1/cwe/version":
        return _json_response(
            {
                "ContentVersion": "4.20",
                "ContentDate": "2026-07-16",
                "TotalWeaknesses": 1000,
                "TotalCategories": 400,
                "TotalViews": 50,
            }
        )
    number = request.url.path.rsplit("/", 1)[-1]
    assert request.url.path == f"/api/v1/cwe/weakness/{number}"
    return _json_response(
        {
            "Weaknesses": [
                {
                    "ID": "999" if wrong_id else number,
                    "Name": f"Example weakness {number}",
                    "Description": f"Official weakness description for {number}.",
                    "PotentialMitigations": [
                        {"Phase": ["Implementation"], "Description": "Validate input."}
                    ],
                }
            ]
        }
    )


def _mitre_client(requests: list[str], *, wrong_id: bool = False) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(
            lambda request: _mitre_response(request, requests, wrong_id=wrong_id)
        ),
        follow_redirects=False,
    )


def test_official_download_uses_only_labeled_cwes_and_writes_verified_manifest(
    corpus_cache: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    requests: list[str] = []
    monkeypatch.setattr(case_corpus, "_make_client", lambda: _mitre_client(requests))

    result = case_corpus.prepare_case_corpus(REPO_ROOT, corpus_cache)

    assert result.status == "official"
    assert result.document_count == 8
    assert requests == [
        "https://cwe-api.mitre.org/api/v1/cwe/version",
        *(f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{item[4:]}" for item in EXPECTED_IDS),
    ]
    corpus = load_verified_corpus(result.root, result.manifest_path)
    assert len(corpus.documents) == 8
    assert {entry.source_url for entry in corpus.entries} == {
        f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{item[4:]}" for item in EXPECTED_IDS
    }
    assert {entry.publisher for entry in corpus.entries} == {"MITRE CWE Program"}
    assert {entry.license for entry in corpus.entries} == {"MITRE CWE Terms of Use"}
    assert {entry.source_revision for entry in corpus.entries} == {"CWE 4.20"}
    assert {entry.source_date for entry in corpus.entries} == {"2026-07-16"}
    assert all("Copyright" in document.text for document in corpus.documents)
    assert all("Terms of Use" in document.text for document in corpus.documents)
    coverage = json.loads(result.coverage_path.read_text(encoding="utf-8"))
    assert coverage["requested_cwe_ids"] == EXPECTED_IDS
    assert coverage["covered_cwe_ids"] == EXPECTED_IDS
    assert coverage["missing_cwe_ids"] == []
    assert coverage["scanner_cases"]["py001-direct-negative"] == []
    assert coverage["scanner_cases"]["py001-direct-positive"] == ["CWE-95"]
    assert coverage["rag_cases"]["direct_parameterized_queries"] == ["CWE-89"]
    assert coverage["rag_cases"]["abstain_without_evidence"] == []


def test_ninth_valid_case_cwe_is_selected_and_downloaded(
    corpus_cache: Path,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_root = tmp_path_factory.mktemp("r")
    evaluation = repo_root / "data" / "evaluation"
    evaluation.mkdir(parents=True)
    (evaluation / "scanner_cases.json").write_bytes(
        (REPO_ROOT / "data/evaluation/scanner_cases.json").read_bytes()
    )
    rag_cases = json.loads((REPO_ROOT / "data/evaluation/rag_cases.json").read_text("utf-8"))
    rag_cases["cases"][0]["knowledge_cwe_ids"].append("CWE-22")
    (evaluation / "rag_cases.json").write_text(json.dumps(rag_cases), encoding="utf-8")
    requests: list[str] = []
    monkeypatch.setattr(case_corpus, "_make_client", lambda: _mitre_client(requests))

    result = case_corpus.prepare_case_corpus(repo_root, corpus_cache)

    assert result.status == "official"
    assert result.document_count == 9
    assert len(load_verified_corpus(result.root, result.manifest_path).documents) == 9
    assert "https://cwe-api.mitre.org/api/v1/cwe/weakness/22" in requests
    coverage = json.loads(result.coverage_path.read_text(encoding="utf-8"))
    assert coverage["requested_cwe_ids"] == ["CWE-22", *EXPECTED_IDS]
    assert coverage["rag_cases"]["direct_parameterized_queries"] == ["CWE-22", "CWE-89"]


def test_total_official_response_budget_degrades_before_unbounded_download(
    corpus_cache: Path,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_root = tmp_path_factory.mktemp("r")
    evaluation = repo_root / "data" / "evaluation"
    evaluation.mkdir(parents=True)
    (evaluation / "scanner_cases.json").write_bytes(
        (REPO_ROOT / "data/evaluation/scanner_cases.json").read_bytes()
    )
    rag_cases = json.loads((REPO_ROOT / "data/evaluation/rag_cases.json").read_text("utf-8"))
    # 84 additional small, valid CWE IDs exceed the 16 MB aggregate response
    # budget while remaining within the 128-ID startup selection cap.
    extra_ids = list(range(1000, 1084))
    for offset in range(0, len(extra_ids), 3):
        batch = extra_ids[offset : offset + 3]
        case = rag_cases["cases"][0].copy()
        case["case_id"] = f"extra_cwe_{batch[0]}"
        case["knowledge_cwe_ids"] = [f"CWE-{number}" for number in batch]
        rag_cases["cases"].append(case)
    (evaluation / "rag_cases.json").write_text(json.dumps(rag_cases), encoding="utf-8")
    shutil.copytree(REPO_ROOT / "data/knowledge", repo_root / "data/knowledge")
    requests: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/cwe/version":
            return _mitre_response(request, requests)
        requests.append(str(request.url))
        number = request.url.path.rsplit("/", 1)[-1]
        return _json_response(
            {
                "Weaknesses": [
                    {
                        "ID": number,
                        "Name": f"Weakness {number}",
                        "Description": "x" * 200_000,
                    }
                ]
            }
        )

    monkeypatch.setattr(
        case_corpus,
        "_make_client",
        lambda: httpx.Client(transport=httpx.MockTransport(respond), follow_redirects=False),
    )

    result = case_corpus.prepare_case_corpus(repo_root, corpus_cache)

    assert result.status == "fallback"
    assert result.document_count == 1
    coverage = json.loads(result.coverage_path.read_text(encoding="utf-8"))
    assert coverage["reason"] == "official_total_response_too_large"
    assert coverage["covered_cwe_ids"] == []


def test_startup_official_collection_has_overall_deadline_without_waiting(
    corpus_cache: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [0.0]
    requests: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        now[0] += 31.0
        return _mitre_response(request, requests)

    monkeypatch.setattr(case_corpus, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        case_corpus,
        "_make_client",
        lambda: httpx.Client(transport=httpx.MockTransport(respond), follow_redirects=False),
    )

    result = case_corpus.prepare_case_corpus(REPO_ROOT, corpus_cache)

    assert result.status == "fallback"
    coverage = json.loads(result.coverage_path.read_text(encoding="utf-8"))
    assert coverage["reason"] == "official_deadline_exceeded"
    assert len(requests) <= 3


def test_offline_reuses_only_verified_official_cache(
    corpus_cache: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(case_corpus, "_make_client", lambda: _mitre_client([]))
    initial = case_corpus.prepare_case_corpus(REPO_ROOT, corpus_cache)
    monkeypatch.setattr(
        case_corpus,
        "_make_client",
        lambda: pytest.fail("offline mode attempted an HTTP connection"),
    )

    cached = case_corpus.prepare_case_corpus(REPO_ROOT, corpus_cache, offline=True)

    assert initial.status == "official"
    assert cached.status == "cached"
    assert cached.root == initial.root
    assert cached.document_count == 8
    assert json.loads(cached.coverage_path.read_text(encoding="utf-8"))["status"] == "cached"


def test_offline_without_cache_falls_back_to_project_guide_without_official_claim(
    corpus_cache: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        case_corpus,
        "_make_client",
        lambda: pytest.fail("offline mode attempted an HTTP connection"),
    )

    result = case_corpus.prepare_case_corpus(REPO_ROOT, corpus_cache, offline=True)

    assert result.status == "fallback"
    assert result.document_count == 1
    corpus = load_verified_corpus(result.root, result.manifest_path)
    assert corpus.entries[0].publisher == "SecRAGraph project"
    coverage = json.loads(result.coverage_path.read_text(encoding="utf-8"))
    assert coverage["status"] == "fallback"
    assert coverage["covered_cwe_ids"] == []
    assert coverage["missing_cwe_ids"] == EXPECTED_IDS


def test_corrupted_cache_does_not_retain_official_status(
    corpus_cache: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(case_corpus, "_make_client", lambda: _mitre_client([]))
    initial = case_corpus.prepare_case_corpus(REPO_ROOT, corpus_cache)
    (initial.root / "cwe-89.md").write_text("# Tampered", encoding="utf-8")

    result = case_corpus.prepare_case_corpus(REPO_ROOT, corpus_cache, offline=True)

    assert result.status == "fallback"
    assert json.loads(result.coverage_path.read_text(encoding="utf-8"))["covered_cwe_ids"] == []


@pytest.mark.parametrize("fault", ["wrong_id", "redirect", "oversize"])
def test_untrusted_http_response_never_becomes_official(
    corpus_cache: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        if fault == "redirect":
            return httpx.Response(302, headers={"Location": "https://example.net/private"})
        if fault == "oversize":
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                stream=httpx.ByteStream(b"x" * 300_000),
            )
        return _mitre_response(request, [], wrong_id=True)

    monkeypatch.setattr(
        case_corpus,
        "_make_client",
        lambda: httpx.Client(transport=httpx.MockTransport(respond), follow_redirects=False),
    )

    result = case_corpus.prepare_case_corpus(REPO_ROOT, corpus_cache)

    assert result.status == "fallback"
    assert result.document_count == 1
    assert json.loads(result.coverage_path.read_text(encoding="utf-8"))["covered_cwe_ids"] == []


def test_prepare_script_reports_machine_readable_degraded_status(
    corpus_cache: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from scripts.prepare_case_corpus import main

    exit_code = main(
        ["--repo-root", str(REPO_ROOT), "--cache-root", str(corpus_cache), "--offline"]
    )

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "fallback"
    assert output["document_count"] == 1
    assert Path(output["manifest_path"]).is_file()
    assert Path(output["coverage_path"]).is_file()
