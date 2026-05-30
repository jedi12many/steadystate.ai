# steadystate container image: Python + the package + kubectl (for the k8s/rancher sources).
#
#   docker build -t ghcr.io/jedi12many/steadystate:latest .
#   docker run --rm -v "$PWD:/data" ghcr.io/jedi12many/steadystate \
#       scan plan.json --source terraform --to console
#
# Terraform/Azure (Example 1) doesn't use this image -- it installs steadystate in the CI
# runner. This image is for the in-cluster CronJob (Example 2) and any container host.

FROM python:3.12-slim AS build
WORKDIR /src
COPY . .
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.12-slim
# kubectl for the kubernetes source (`kubectl get -o json`) and the rancher source (it reads
# a Fleet GitRepo via `kubectl get gitrepo -o json`). Harmless for the other sources.
ARG KUBECTL_VERSION=v1.31.3
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && curl -fsSL -o /usr/local/bin/kubectl \
      "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
 && chmod +x /usr/local/bin/kubectl \
 && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl
# Run unprivileged. The SQLite memory (new/recurring/resolved, mute/snooze, LLM spend)
# belongs on a mounted volume at /data; pass `--state /data/state.db`.
RUN useradd -u 10001 -m runner
USER runner
WORKDIR /data
ENTRYPOINT ["steadystate"]
CMD ["--help"]
