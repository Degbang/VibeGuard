# VibeGuard

Explainable risk assessment for AI-generated Java microservices.

MSc Cyber Security and Digital Forensics thesis project, KNUST.
See `CLAUDE.md` for architecture, coding standards, and build order,
and `IMPLEMENTATION_LOG.md` for how implementation has diverged from
the original plan.

## Setup

```bash
python3.10 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**If `import scipy` (or anything importing `scikit-learn`/`shap`) fails with a
`dlopen` error mentioning `_propack`/`__DATA/__thread_bss`:** this is a known
incompatibility between PyPI's prebuilt `scipy` wheel and very new macOS
builds — confirmed reproducible on a fresh venv, not specific to one checkout.
Fix by building `scipy` from source against Homebrew's toolchain:

```bash
brew install gcc openblas
PKG_CONFIG_PATH="/opt/homebrew/opt/openblas/lib/pkgconfig" \
  pip install --no-binary scipy --force-reinstall "scipy==1.15.3"
pip install --no-deps --force-reinstall "numpy==1.26.3"  # restore the pinned version
```

## Run with Docker (easiest - no local Python/venv setup needed)

Requires only Docker. Scan any Java project by path, from anywhere on disk:

```bash
scripts/scan.sh /path/to/your/java/project
```

This builds the image on first use (cached after that) and runs the scan
inside a container with the exact pinned dependencies from `requirements.txt`.
The project being scanned is mounted **read-only** - the scanner never writes
to, executes, or evaluates any code in the project it's scanning, the same
guarantee the native (non-Docker) path makes. Works for a directory or a
single supported file (`pom.xml`, `build.gradle(.kts)`, a `.java` file, or a
conventional config file):

```bash
scripts/scan.sh ~/code/some-java-service
scripts/scan.sh ~/code/some-java-service --timeout 10   # extra args pass through
scripts/scan.sh ./pom.xml
```

To build and run the image manually instead of via the wrapper script:

```bash
docker build -t vibeguard .
docker run --rm -v /absolute/path/to/project:/scan-target:ro vibeguard /scan-target
```

## Run from a local Python install

From the repository root, scan a Java project through all five layers:

```bash
.venv/bin/python main.py data/sample_apps/ai-account-recovery-service
```

Replace the sample path with your Java project directory or a single supported
file. The report includes parsing outcomes, scored CWE findings with file/line
references, the Random Forest prediction, and SHAP feature contributions.
Exit code `0` means all discovered files parsed successfully with no rejected
paths or findings. Exit code `1` indicates findings or a scan failure; inspect
the report for the reason.

To capture the scan report and the full labelled-dataset evaluation together:

```bash
.venv/bin/python -m evaluation.thesis_orchestrator \
  data/sample_apps/ai-account-recovery-service \
  --output-dir dist/thesis_artifacts
```

The command prints a run directory containing scan text/JSON, evaluation
JSON/CSV, manifests, and a combined `thesis_summary.json`. Artifact capture
can succeed even when the scan reports findings or a captured error; inspect
`scan/scan_report.json` for `exit_code` and `error_message`.

To evaluate the model alone or run the project checks:

```bash
.venv/bin/python -m evaluation.evaluate
.venv/bin/pytest -q
.venv/bin/mypy .
.venv/bin/ruff check .
.venv/bin/black --check .
git diff --check
```

Scanning and model evaluation run locally. Target Java source is parsed, never
executed. Findings are heuristic candidates; the implementation log documents
coverage limits and the distinction between controlled-dataset results and
real-world generalization.
