# Threat Intelligence

This module is a rebuild boundary for **Phish-Hunter**. Keep module-specific logic, schemas, enrichments, graph rules, reporting and AI-agent prompts inside this directory. The existing canonical implementation is wrapped rather than duplicated so other application behavior remains stable.

## Files

`engine.py` → canonical engine adapter

`api.py` → stable module API boundary

`manifest.py` → deep capabilities/evidence/integrations contract

`schemas.py` → evidence/case data structures

`enrichment.py` → connector planning/status boundary

`graph.py` → relationship types

`reporting.py` → report/export boundary

`agent.py` → evidence-first AI-agent contract

## Rule

External provider output is never invented. Distinguish observed evidence, correlated evidence, inference and items requiring verification.
