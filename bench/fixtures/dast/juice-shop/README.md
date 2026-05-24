# DAST benchmark fixture: OWASP Juice Shop

OWASP Juice Shop is a deliberately-vulnerable Node.js web app. Running
ZAP baseline against it surfaces a stable set of HTTP-layer alerts
(CSP, cross-origin, dangerous JS functions, etc.).

`bench/run.py --dast` orchestrates the full lifecycle:

1. `docker run` Juice Shop on `127.0.0.1:3000` (image digest pinned in
   `expected.json`).
2. Wait for the container to respond on `/`.
3. `secscan dast --target http://host.docker.internal:3000/ ...` —
   secscan internally manages a docker volume + alpine helper +
   zap-baseline.py + report extraction.
4. Parse the findings, compare pluginid set against
   `expected.json#expected_findings`.
5. Stop the Juice Shop container.

Expected wall-clock: **2–4 minutes** dominated by the ZAP baseline scan.

## Image digest rotation

When ZAP, Juice Shop, or alpine push a new image:

1. `docker pull <repo>:<tag>`
2. `docker inspect --format='{{index .RepoDigests 0}}' <repo>:<tag>`
3. Update the corresponding entry under `expected.json#image_pinning`
   AND the matching constant in `src/secscan/scanners/dast/`.
4. Re-run `bench/run.py --dast` to refresh the expected findings if
   the upstream tools' default rules changed.

## Skipping

`bench/run.py` (without `--dast`) skips this fixture by design — ZAP is
the slowest scanner by a wide margin. Use `--dast` only when you
explicitly want a fresh DAST measurement.
