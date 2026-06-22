# Contributing to ReconX

## Getting Started

```bash
git clone https://github.com/<org>/reconx
cd reconx
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Project Structure

See `RECONX_PRD.md` Section 10.1 for the full repository layout.

## Coding Standards

- Type hints required on all public functions; `mypy --strict` enforced in CI
- No bare `except:` — every catch must name the exception type(s)
- No `eval`, `exec`, or `subprocess` with `shell=True`
- All dependencies pinned via lockfile; new deps need a one-line justification in the PR

## Running Checks

```bash
mypy --strict reconx
ruff check reconx
bandit -r reconx/
pytest
```

## PR Checklist

- [ ] Does this change add a network call? If yes, is it timeout-bounded and counted against the "single fetch" rule?
- [ ] Does this change touch anything that could turn a passive check into an active one? If yes, it needs a maintainer security sign-off.
- [ ] New adversarial test case added if this touches parsing of attacker-controlled data?
- [ ] `bandit`/`mypy`/`pip-audit` clean?
