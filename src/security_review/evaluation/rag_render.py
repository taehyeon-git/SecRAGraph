"""Stable, bounded public evidence for the offline RAG graph evaluation."""

from __future__ import annotations

import html
import json
import re

from security_review.evaluation.rag_models import RagCaseResult, RagEvaluation, RagMetric

_MARKDOWN_CONTROL = re.compile(r"([\\`*_\[\]#|>])")


def _escape(value: object, *, limit: int = 500) -> str:
    normalized = " ".join(str(value).split())
    if len(normalized) > limit:
        normalized = normalized[: limit - 1].rstrip() + "…"
    return _MARKDOWN_CONTROL.sub(r"\\\1", html.escape(normalized, quote=True))


def render_rag_json(evaluation: RagEvaluation) -> str:
    """Serialize only the validated evaluation contract, with stable key order."""

    return (
        json.dumps(
            evaluation.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _metric_row(label: str, metric: RagMetric) -> str:
    rate = "N/A" if metric.value is None else f"{metric.value:.3f}"
    return (
        f"| {label} | {metric.numerator} | {metric.denominator} | "
        f"{metric.not_applicable} | {rate} |"
    )


def _case_lines(case: RagCaseResult) -> list[str]:
    status = "PASS" if case.passed else "FAIL"
    lines = [
        f"### {_escape(case.case_id)} — {status}",
        "",
        f"- Expected / actual outcome: {_escape(case.expected_outcome)} / "
        f"{_escape(case.actual_outcome)}",
        f"- Completed nodes: {_escape(' → '.join(case.completed_nodes))}",
        f"- Expected nodes: {_escape(' → '.join(case.expected_completed_nodes))}",
        f"- Attempts: {case.attempts}",
        f"- Failure stage: {_escape(case.failure_stage or 'none')}",
        f"- Expected failure stage: {_escape(case.expected_failure_stage or 'none')}",
        f"- Cited IDs: {_escape(', '.join(case.cited_ids) or 'none')}",
        "- Search queries:",
    ]
    lines.extend(f"  - {_escape(query, limit=200)}" for query in case.search_queries)
    if not case.search_queries:
        lines.append("  - none")
    lines.extend(["", "#### Retrieved candidates (metadata only)", ""])
    if case.retrieved:
        for source in case.retrieved:
            score = "none" if source.score is None else f"{source.score:.4f}"
            lines.append(
                f"- {_escape(source.id)} — {_escape(source.title)}; "
                f"section: {_escape(source.section or 'none')}; "
                f"page: {_escape(source.page if source.page is not None else 'none')}; "
                f"URL: {_escape(source.source_url or 'none')}; score: {score}"
            )
    else:
        lines.append("- none")
    lines.extend(["", "#### Cited evidence", ""])
    if case.cited_evidence:
        for evidence in case.cited_evidence:
            lines.extend(
                [
                    f"- {_escape(evidence.id)} — {_escape(evidence.title)}; "
                    f"section: {_escape(evidence.section or 'none')}; score: {evidence.score:.4f}",
                    f"  - Excerpt: {_escape(evidence.excerpt, limit=240)}",
                ]
            )
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            f"- Answer: {_escape(case.answer or 'none')}",
            f"- Warnings: {_escape(', '.join(case.warnings) or 'none')}",
            f"- Error: {_escape(case.error or 'none')}",
            "- Checks:",
        ]
    )
    for name, result in case.checks.model_dump().items():
        value = "N/A" if result is None else "pass" if result else "fail"
        lines.append(f"  - {_escape(name)}: {value}")
    lines.append("")
    return lines


def render_rag_markdown(evaluation: RagEvaluation) -> str:
    """Render a human-readable trace without exposing raw graph state or uncited chunks."""

    lines = [
        "# SecRAGraph offline RAG evidence",
        "",
        f"- Result: {'PASS' if evaluation.passed else 'FAIL'} "
        f"({sum(case.passed for case in evaluation.cases)}/{len(evaluation.cases)} cases)",
        f"- Manifest SHA-256: {_escape(evaluation.manifest_sha256)}",
        f"- Indexed corpus SHA-256: {_escape(evaluation.corpus_sha256)}",
        f"- Corpus digest kind: {_escape(evaluation.corpus_digest_kind)} "
        "(canonical indexed chunk records, not raw guide file bytes)",
        f"- Embedding algorithm version: {_escape(evaluation.embedding_algorithm_version)}",
        f"- Git revision: {_escape(evaluation.git_revision)}",
        f"- Git dirty: {str(evaluation.git_dirty).lower()}",
        f"- Source fingerprint: {_escape(evaluation.source_fingerprint)}",
        "",
        "## Metrics",
        "",
        "Each denominator counts only applicable cases; N/A counts the remaining cases.",
        "",
        "| Contract | Numerator | Denominator | N/A | Rate |",
        "| --- | ---: | ---: | ---: | ---: |",
        _metric_row("Path match", evaluation.metrics.path_match),
        _metric_row("Retrieval hit@k", evaluation.metrics.retrieval_hit_at_k),
        _metric_row("Cited section correctness", evaluation.metrics.cited_section_correctness),
        _metric_row("Citation ID validity", evaluation.metrics.citation_id_validity),
        _metric_row("Source alignment", evaluation.metrics.source_alignment),
        _metric_row("Abstention success", evaluation.metrics.abstention_success),
        "",
        "## Cases",
        "",
    ]
    for case in evaluation.cases:
        lines.extend(_case_lines(case))
    return "\n".join(lines).rstrip() + "\n"
