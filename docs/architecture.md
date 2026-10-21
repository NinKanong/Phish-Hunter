# Architecture

PhishGuard is a monolithic Python application with clear module boundaries. The default local deployment is a single Uvicorn process and SQLite database. Production can move the database to PostgreSQL and place Gunicorn/Uvicorn behind Nginx.

Dynamic malware execution is intentionally not part of the web process. `phishhunter.sandbox.manager` is an integration boundary that can submit an artifact to an isolated sandbox service.
