# Local NIST SSDF PDF ingestion check

On 2026-10-27, I downloaded the official **NIST SP 800-218, SSDF Version 1.1** PDF for local evaluation. The PDF binary is ignored by Git and is not redistributed from this repository. The reviewed [NIST publication record](https://csrc.nist.gov/pubs/sp/800/218/final) is the source of the title, publisher, final status and date. Recheck the record and the PDF's own notices before reuse.

| Check | Observed value |
| --- | --- |
| Local file | `data/knowledge/official/NIST.SP.800-218.pdf` |
| Size | 739,891 bytes |
| SHA-256 | `617746e553a9e2da49bfbd4eef0dfc3094758a39b869314e4173ac36605cde22` |
| PDF pages | 36 |
| Manifest | [Pinned example](../../data/knowledge/official.example.json) |
| Keyless sync preview | 36 desired page documents, 0 stale documents |

To reproduce, obtain the PDF from the NIST record and verify its SHA-256. Copy `official.example.json` to `data/knowledge/official/manifest.json`, place the PDF beside it, and run `security-review sync-corpus data/knowledge/official --chunk-size 500 --overlap 50` against an initialized local Qdrant collection. A changed publisher file must fail its pinned hash until reviewed and recorded as a new revision. Preview does **not** apply vectors or prove answer quality; `--apply` requires an embedding provider key and an explicit operator decision. The local preview used a separate loopback Qdrant test collection and made no corpus changes.

This check confirms byte provenance, manifest validation, PDF page extraction and the planned Qdrant document IDs. It does not establish that a PDF is harmless, that its reuse rights are unrestricted, or that RAG answers are factual. The parser's transient decompression memory is not bounded by the post-extraction character limits; use the resource controls described in [corpus guidance](../official-corpus.md).
