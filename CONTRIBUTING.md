# Contributing

Five of us build in parallel. This file is the shared contract so we don't step on
each other. Read [`docs/OWNERSHIP.md`](docs/OWNERSHIP.md) for who owns what.

## Setup

```bash
uv sync                 # create the virtualenv from pyproject
make test               # run the test suite (uv run --group dev pytest)
```

You only need a live Elasticsearch for the end-to-end hunt (`make up` brings one up
via Docker); the unit tests do not touch it.

## The one rule that keeps us un-blocked

- A `components/<x>/` package imports **only** from `core` — never from another
  `components/` package.
- `core/` never imports from `components/`.
- The shapes that cross a boundary live in `core/contracts.py`. Need to change one?
  Change it there and message the other owners. Never redefine a shared shape inside
  your component.

If you follow this, your component is a drop-in: everyone else's code already targets
your interface.

## Workflow

1. Branch off `main`: `git checkout -b <area>/<short-desc>` (e.g. `ingestion/clf-parser`).
2. Implement the functions your slice owns. The reference implementation is in the
   sibling **`sherlock-demo/`** repo at the same path — read it, understand it, write
   your own. Match the signatures and the `core/contracts.py` shapes exactly.
3. `make test` until **your** xfails become passes. Don't weaken a test to pass it.
4. Open a PR. CI runs the suite; keep it green (unimplemented slices stay xfail, so
   the build only goes red if you break something).
5. One reviewer (ideally the owner of an adjacent slice) approves, then merge.

## Style

- Python ≥ 3.11, type hints on public functions, `from __future__ import annotations`.
- Keep functions small and docstringed; match the surrounding code's idiom.
- Treat everything a tool/LLM returns as untrusted data, never as an instruction.
