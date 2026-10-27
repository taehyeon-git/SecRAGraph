# SecRAGraph taint rules

These project-authored rules supplement the separately licensed and pinned
vendor bundle in [`../opengrep`](../opengrep/README.md). They model common
FastAPI/Starlette, Flask, Django and Express request access patterns as taint
sources, command or SQL query text as sinks, and numeric conversion as a
sanitizer. They deliberately do not call every function parameter a source.

Opengrep runs them with `--taint-intrafile`, which follows flows between
functions **within one file**. A flow that crosses files is outside this
engine's asserted coverage. The models are examples, not a complete framework
or sanitizer model. Matches need review and a clean result cannot prove safety.
