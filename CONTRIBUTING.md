# Contributing to Nemesis

Thanks for helping improve Nemesis. This project scans real systems, so quality
and safety matter — please read the short checklist below.

## Development setup

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate    |  macOS/Linux:  source .venv/bin/activate
pip install -r requirements-dev.txt
pre-commit install        # optional but recommended
```

## Before you push

The CI runs these exact checks — run them locally to get a green build:

```bash
ruff check .                                   # lint
pytest                                         # tests
bandit -c pyproject.toml -r core modules tools webapp \
       --severity-level medium --confidence-level medium   # SAST gate
```

## Adding a technique module

1. Create a subclass of `BaseModule` in the right `modules/<category>/` folder and
   decorate it with `@register` (see [`modules/base.py`](modules/base.py)).
2. Give it a **unique** `id`, a `name`, a `category`, and a valid `scope`
   (`"origin"` or `"page"`). The test suite enforces these invariants.
3. Regenerate the build manifest so the frozen `.exe` picks it up:

   ```bash
   python tools/gen_manifest.py
   ```

   `tests/test_manifest_sync.py` fails if you forget this step.

## Ground rules

- **Non-abusive by default.** Respect the rate limiter; never add flooding/DoS
  behavior. Payloads must be safe, out-of-band canaries where possible.
- **Authorized targets only.** Do not commit code that scans third parties by
  default or phones home.
- Keep findings actionable: set an accurate `Severity`, `confidence`, and
  `remediation`.

## Commit / PR

- Keep PRs focused; describe the technique or fix and how you verified it.
- Ensure lint, tests, and the Bandit gate pass.
