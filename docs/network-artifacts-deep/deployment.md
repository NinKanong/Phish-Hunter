# Deployment Notes

The current local implementation is runnable with the existing Cyber-Phish-k4 FastAPI application and its configured database/storage. Optional integrations can be added for Redis/Celery, PostgreSQL, object storage, Elasticsearch, Zeek, Suricata, Arkime, Malcolm, MaxMind GeoIP, YARA and external threat-intelligence providers.

Do not treat the included connector boundaries as active network lookups. Configure and approve outbound integrations explicitly.
