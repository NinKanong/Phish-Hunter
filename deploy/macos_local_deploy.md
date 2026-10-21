# Macos Local deployment

1. Provision a Linux machine or supported Python hosting environment.
2. Copy this repository.
3. Create a Python 3.12+ virtual environment.
4. Install `requirements/prod.txt`.
5. Set `.env` with a strong secret and production database.
6. Run `python -m phishhunter.seed` once.
7. Start `gunicorn -c gunicorn.conf.py phishhunter.asgi:app`.
8. Put HTTPS in front of the Python service.

For dynamic analysis, use a separate isolated sandbox host rather than running samples on this web host.
