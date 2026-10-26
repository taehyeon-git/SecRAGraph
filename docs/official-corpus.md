# Curating an official PDF corpus

PDF support is limited to explicit, local files named in a version 1 `manifest.json`. The sync command never discovers PDFs recursively or downloads publisher links. A manifest SHA-256 authenticates the bytes selected by the operator; it does not certify that a file is harmless or that its reuse rights are clear. The CLI runs in the local host process, so it does not inherit the Compose API container's 1 CPU / 1 GB memory limits. For an operational corpus, use a disposable container or equivalent OS resource limits and mount the corpus read-only. pypdf does not execute PDF JavaScript or attachments here; this pipeline does not OCR scanned pages, follow links, or open embedded files.

## Reviewed acquisition catalog

These entries are a starting catalog, not a claim that the files have been downloaded, indexed, or cleared for redistribution. Recheck the publisher landing page immediately before acquisition and retain the exact version and date in the local manifest.

One NIST SSDF Version 1.1 PDF was separately acquired for a local, non-redistributed check. Its exact SHA-256, [pinned example manifest](../data/knowledge/official.example.json), and preview result are recorded in the [local evidence note](evidence/official-pdf-local.md); the catalog as a whole has not been ingested.

| Publication | Status and date | Canonical publisher source | Acquisition notes |
| --- | --- | --- | --- |
| NIST SP 800-218, *Secure Software Development Framework (SSDF) Version 1.1* | Final, 2022-02-03 | [NIST publication record](https://csrc.nist.gov/pubs/sp/800/218/final) | NIST currently identifies this as final. The publication record links the official publication and DOI. Check errata, revisions, and marked third-party material before reuse. |
| NIST SP 800-218 Rev. 1, *SSDF Version 1.2* | Initial public draft, 2025-12-17; comment period closed 2026-01-30 | [NIST draft record](https://csrc.nist.gov/pubs/sp/800/218/r1/ipd) | This remains a draft in the NIST catalog. Do not describe it as a final standard; replace or retain it deliberately when NIST publishes a final revision. |
| CISA et al., *Shifting the Balance of Cybersecurity Risk: Principles and Approaches for Secure-by-Design and -Default* | Published joint guide, 2023; confirm current issue at download | [Official CISA PDF](https://www.cisa.gov/sites/default/files/2023-06/principles_approaches_for_security-by-design-default_508c.pdf) and [CISA Secure by Design resources](https://www.cisa.gov/securebydesign) | Joint publication credits multiple U.S. and international agencies. Record the exact PDF issue/date and review all credited contributors' reuse terms. |

NIST states that material marked as copyrighted is excluded from its general public-information reuse statement, and that some NIST Technical Series works are authored by third parties. CISA materials can also be joint works. Do not infer redistribution permission solely from a government-hosted URL. Review document notices, contributors, and applicable terms; for uncertain rights, keep the file local and seek permission before sharing it. See [NIST copyright guidance](https://www.nist.gov/copyrights-disclaimers) and [NIST Technical Series publication notes](https://www.nist.gov/nist-research-library/nist-publications).

## Acquire one file and create its manifest entry

Download a single reviewed PDF manually from its catalogued publisher URL into a local directory such as `data/knowledge/official/`. Do not use a crawler or a broad link downloader. This repository ignores PDF binaries under `data/knowledge/`; do not force-add them. Inspect the title page and publisher record, confirm final/draft status, date, publisher, source URL, and rights note, then calculate SHA-256 over the original bytes:

```powershell
$pdf = 'data/knowledge/official/sp-800-218.pdf'
(Get-FileHash -Algorithm SHA256 $pdf).Hash.ToLowerInvariant()
```

Add the relative file path and all required provenance values to that directory's `manifest.json`:

```json
{
  "version": 1,
  "corpus_id": "official-security-guidance",
  "documents": [
    {
      "path": "sp-800-218.pdf",
      "title": "Secure Software Development Framework (SSDF) Version 1.1",
      "publisher": "National Institute of Standards and Technology",
      "source_url": "https://csrc.nist.gov/pubs/sp/800/218/final",
      "license": "Review the PDF notices and NIST reuse guidance; local use only until cleared",
      "source_revision": "SP 800-218 final, Version 1.1",
      "source_date": "2022-02-03",
      "sha256": "<lowercase SHA-256 of the exact PDF bytes>"
    }
  ]
}
```

The manifest's `license` field is a rights note, not a license grant. Keep every downloaded file inside the corpus directory and ensure its path has no symlink, junction, or reparse-point component. A changed PDF needs a freshly reviewed manifest entry and digest. Keep its corpus ID and relative path when it is a revision so preview/apply reconciliation removes obsolete chunks for that source while preserving other corpora.

## Verify and sync locally

The CLI verifies every listed file's bounded raw bytes and SHA-256 before parsing. It then rejects encrypted, invalid, oversized, over-page-limit, and textless PDFs. Extracted text remains untrusted evidence: instructions in the source are not graph instructions. Page citations use one-based PDF page numbers and the manifest's publisher URL.

```powershell
uv sync --frozen --dev
uv run security-review sync-corpus data/knowledge/official --chunk-size 500 --overlap 50
# Review the preview and local rights/provenance before applying:
uv run security-review sync-corpus data/knowledge/official --chunk-size 500 --overlap 50 --apply
```

For keyless verification, run the unit tests and `uv run python -m scripts.run_rag_evidence`. These exercise deterministic extraction, indexing, citations, and graph trust boundaries without contacting an LLM provider. Live semantic retrieval requires the configured embedding provider and matching Qdrant collection; a real model answer still needs human source review. Do not report synthetic fixtures as evidence of LLM factual quality.

## Parser bounds and remaining risk

The loader caps a PDF at 5 MB, a corpus at 20 MB, 200 pages per PDF, 100,000 extracted characters per page, and 2,000,000 extracted characters per PDF. It rejects raw page-content streams larger than 2 MB before text extraction where pypdf exposes their bytes. The extracted-character limits are checked only after pypdf decodes page content; they do not cap the transient decoded stream allocation. A small Flate-compressed content stream can therefore expand substantially before the character check rejects it, and parser CPU or memory use is not strictly bounded by these limits. Existing aggregate document and chunk limits apply after extraction. Only use trusted sources, keep ingestion local and explicit, and run it under OS or container CPU and memory limits. A digest proves byte identity, not benign content.
