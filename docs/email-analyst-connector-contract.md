# Email Analyst Connector Contract

A connector should implement the Email Analyst enrichment contract rather than modifying the analyzer itself.

## Input

```json
{
  "indicator_type": "url|domain|ip|hash|email",
  "indicator": "...",
  "scan_id": "...",
  "evidence_id": "..."
}
```

## Output

```json
{
  "provider": "example",
  "indicator": "...",
  "found": false,
  "score": null,
  "confidence": 0,
  "raw": {},
  "status": "completed|not-configured|error",
  "observed_at": "..."
}
```

A connector must never turn an unavailable lookup into a positive finding.
