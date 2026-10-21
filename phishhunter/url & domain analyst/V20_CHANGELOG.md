# V20 Change Log

## Fixed

- Replaced the fake landing-page progress timer with a real asynchronous scan job.
- Added SSE event streaming for actual engine progress.
- Moved the blocking analyzer execution to a worker thread so the web/SSE loop stays responsive.
- Added job status and result endpoints.
- Added browser reconnect support through `?job=<id>`.
- Removed first-screen profile controls, upload controls and authorization checkbox from the minimal intake.
- Kept the deep profile as the default server-side investigation path.

## Deep pipeline

The V20 progress stream exposes real module states for URL/domain anatomy, DNS, RDAP, CT, HTTP, TLS, infrastructure, reputation, breach status, detections, graph, risk, evidence, geography, services, attack surface, OSINT and reasoning stages.
