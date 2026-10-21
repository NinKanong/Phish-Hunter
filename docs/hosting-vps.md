# VPS hosting

Ubuntu/Debian example:

```bash
sudo apt update
sudo apt install -y python3 python3-venv nginx
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements/prod.txt
cp .env.example .env
python -m phishhunter.seed
gunicorn -c gunicorn.conf.py phishhunter.asgi:app
```

Put Nginx in front, issue a Let's Encrypt certificate with Certbot, and bind Gunicorn to localhost only.
