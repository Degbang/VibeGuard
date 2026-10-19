# VibeGuard: explainable risk assessment for AI-generated Java microservices.
#
# Packages the CLI with its exact pinned dependencies (requirements.txt) so
# scanning any Java project needs nothing installed on the host beyond
# Docker itself. The container never executes or evaluates any code from
# the project it scans - it only parses Java source into an AST, the same
# guarantee vibeguard/layer1_static/scanner.py states for the tool itself.
#
# Build once:
#   docker build -t vibeguard .
#
# Scan any local project (read-only mount - the scanner never needs write
# access to the project it's scanning):
#   docker run --rm -v /absolute/path/to/project:/scan-target:ro vibeguard /scan-target
#
# Or use scripts/scan.sh, which wraps this exact command.

FROM python:3.10-slim

# build-essential: some pinned dependencies (tree-sitter, tree-sitter-java,
# scikit-learn, shap) may fall back to building a native extension from
# source if no pre-built wheel matches the exact image platform/arch.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python", "main.py"]
