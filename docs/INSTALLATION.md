# INSTALLATION.md

## Requirements

- Python **3.11+** (the lockfile builds on 3.12; `pyproject.toml` requires `>=3.11`).
- `uv` (recommended) or a plain `pip` + `venv`.
- No Java required for the default **mock** build. APK-level parsing with
  Androguard would need a Java-supporting JDK only if Java-based Dex analysis
  is enabled — this is not used in the current build, which parses simulated
  artifact descriptors instead of real APK bytes.

## Install with uv (recommended)

```bash
cd findroid-bd-400
uv sync --extra dev
```

This creates `.venv`, installs the package in editable mode together with the
`dev` extras (`pytest`, `pytest-cov`, `ruff`, `mypy`, `pre-commit`).

## Install with pip

```bash
cd findroid-bd-400
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Verify the installation

```bash
uv run findroid --help
uv run pytest -q
```

`findroid --help` prints the pipeline usage block. `pytest -q` should report
the full test suite green.

## What gets installed

- The console script `findroid` → `findroid.cli.main:main`.
- Core dependencies: `pandas`, `numpy`, `scipy`, `scikit-learn`, `pyarrow`,
  `pydantic`, `jinja2`, `PyYAML`, `requests`, `androguard`.

## No-build notes

- `pyproject.toml` uses `[project.scripts]` and a `src/` layout
  (`[tool.setuptools.packages.find] where = ["src"]`), so the CLI is only on
  `PATH` after the editable install.
- `pipeline/01_init.py … 10_report.py` are standalone scripts that run the
  same phases as `findroid run`; they import the package via a `sys.path`
  insert and do not require the console script.