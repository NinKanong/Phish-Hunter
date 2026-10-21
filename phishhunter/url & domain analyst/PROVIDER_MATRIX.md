# Provider Integrity Matrix

The analyst distinguishes these states:

- `live-configured`: credentials/configuration exists and the connector can run.
- `public-observation`: a public source returned an observation.
- `provider-dependent`: a provider is supported but not configured/available.
- `catalog-only`: integration is represented as a capability contract, not queried automatically.
- `not-observed`: the current collection did not return evidence.
- `degraded`: a module failed but the rest of the case continued.

The integration catalog contains 288 named tools/services in the current build and the connector capability registry exposes 778 capability points. These numbers are catalog/capability counts, not claims that all sources are live simultaneously.
