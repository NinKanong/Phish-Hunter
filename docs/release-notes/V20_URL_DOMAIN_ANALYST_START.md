# V20 URL & Domain Analyst

## Start

```bash
python run.py
```

Open:

`/services/url-domain-analyst`

The first screen intentionally contains only one target field and **Start Test!**.

## Live investigation API

- `POST /services/url-domain-analyst/scan`
- `GET /services/url-domain-analyst/scan/{job}/events`
- `GET /services/url-domain-analyst/scan/{job}/status`
- `GET /services/url-domain-analyst/scan/{job}/result`

## Architecture

Executable code: `phishhunter/url_domain_analyst/`

Requested isolated source mirror: `phishhunter/url & domain analyst/`

The scan is passive-first and provider-aware. External API credentials must be configured before a provider is treated as live.
