# REST / GraphQL / WebSocket Contract

## REST
- POST `/api/v23/cases` — create investigation
- GET `/api/v23/cases/{case_id}` — case summary
- GET `/api/v23/cases/{case_id}/status` — job status
- GET `/api/v23/cases/{case_id}/modules/{module}` — module result
- GET `/api/v23/cases/{case_id}/domain` — registration/domain information
- GET `/api/v23/cases/{case_id}/dns` — DNS full stack
- GET `/api/v23/cases/{case_id}/dns/matrix` — resolver matrix
- GET `/api/v23/cases/{case_id}/map` — map state
- GET `/api/v23/cases/{case_id}/map/countries/{iso}` — country detail
- GET `/api/v23/cases/{case_id}/map/locations/{location_id}` — location detail
- POST `/api/v23/cases/{case_id}/isolate` — cross-module isolate
- GET `/api/v23/cases/{case_id}/graph` — graph
- GET `/api/v23/cases/{case_id}/evidence` — evidence ledger
- GET `/api/v23/cases/{case_id}/exports/{format}` — export
- POST `/api/v23/cases/{case_id}/watchlists` — monitoring

## WebSocket
`/ws/v23/cases/{case_id}` events: `job.progress`, `module.updated`, `marker.add`, `marker.update`, `country.update`, `branch.add`, `finding.add`, `evidence.add`, `isolate.changed`.

## GraphQL
Queries: `case`, `domain`, `dns`, `locations`, `branches`, `graph`, `findings`, `evidence`. Mutations: `isolate`, `watch`, `export`.
