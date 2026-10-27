# Runtime CWE Evidence Design

## Intent

The 53 scanner cases and four RAG cases are reproducible evaluations, not the set of allowed user inputs. Normal scans and new knowledge questions should bring the official CWE evidence they need into the same source-cited RAG collection without manually editing evaluation labels or restarting the stack.

## Approaches considered

1. **Fetch the whole MITRE weakness catalog at every start.** This can answer more topics, but performs large downloads and embeddings even when unused.
2. **Reuse the current case-corpus sync for each new CWE.** This is unsafe: an incomplete desired set causes `sync_corpus` to remove existing managed documents, and changing the ID set invalidates the all-or-nothing cache.
3. **Selected: bounded per-CWE acquisition and document replacement.** Extract CWE IDs from actual findings; use a constrained candidate list for new questions; validate each ID against MITRE, cache each document independently, and replace only that document's Qdrant chunks in a separate `secragraph-runtime-cwe-v1` corpus. Keep the fixed evaluations as regression evidence. Runtime sync never calls `sync_corpus()` with a partial desired set.

## Behavior

- For a scan, the graph deduplicates `cwe_ids` from current findings after dependency audit. An optional evidence provider acquires only missing official records, attaches verified MITRE references and indexes their text when embeddings are configured. Current OSV findings have no CWE, and no CVE is inferred from a CWE.
- For a knowledge question, the existing intent classifier also proposes up to eight CWE IDs in structured output. Explicit `CWE-<number>` tokens in the question take priority. The system validates syntax and checks each candidate against the official record; a model suggestion is a search lead, never proof that the weakness is present. CWE concept questions use the RAG route; Text2SQL aggregation questions keep their structured-data route. The RAG route indexes verified missing documents before vector search. A question with no reliable candidate searches the existing corpus and retains the current insufficient-evidence behavior.
- Startup still prepares the benchmark corpus for evidence, and additionally includes all checked-in scanner rule CWE IDs so routine scans begin with their official documents indexed. Runtime additions do not alter the fixed evaluation scores.
- Acquisition is opt-out via a separate automatic-CWE setting; the canonical local `--offline` mode disables it alongside OSV and the model provider. No source text or raw question is sent to MITRE; only validated CWE numbers are sent. Model question classification follows the existing configured model path. User-supplied source text never enters an acquisition URL.
- Cached records are verified by manifest and SHA-256 before use. A corrupt or unavailable record is never represented as official evidence. A cold miss may add bounded latency; warm requests avoid network and re-embedding. Failures preserve scanner findings or the knowledge workflow and add a content-free coverage warning.

## Resource and data boundaries

- Accept at most 64 distinct CWE IDs per scan and eight per question, with a 12-second acquisition budget, at most four in-flight MITRE requests, 256,000 bytes per response and 8,000,000 bytes total per request. Each HTTP connect/read and Qdrant index wait gets the remaining deadline; a blocked provider is reported as partial. Requests above the cap are truncated deterministically and warned about. The existing 30-second scan processing limit remains authoritative.
- Keep no more than 1,024 runtime documents in the dedicated Qdrant corpus, checked against its bounded snapshot before a new ID is indexed. A user may refresh the official startup corpus separately. Limits control unexpected cost and are not evaluation-case counts.
- API runs with a read-only root filesystem. Its cache under the existing 64 MiB tmpfs is limited to 16,000,000 bytes with bounded eviction; Qdrant is the durable index. CLI uses a system temporary cache. Cold requests may fetch again after API restart if the temporary cache is gone; an existing index must remain available and must not be deleted by a small update. Startup and runtime documents may overlap temporarily, so retrieval can return both copies until the startup corpus is separately refreshed.

## Evidence and limitations

- Tests cover manifest count changes, a novel finding CWE, a new natural-language question with a validated CWE suggestion, explicit CWE IDs, cache hit, corruption, concurrency, source validation, index preservation, offline and provider failures, deadlines and caps.
- Without a model/embedding key, CLI scans may attach verified official CWE references, but live model-backed RAG remains unavailable as before. More CWE documents do not create new scanner detection rules. A free-form question can be misclassified; answers remain constrained to retrieved evidence with citation validation.
