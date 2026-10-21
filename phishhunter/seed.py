"""Initialize the database schema without creating demo identities.

Historically this module created a placeholder/demo account during installation,
which made the administrator directory look populated before a real user had
signed up. Phish-Hunter-k4 now keeps the identity store empty until an explicit
registration or `bootstrap_admin.py` command creates an account.
"""

from phishhunter.db.database import init_db


if __name__ == "__main__":
    init_db()
    print("Database schema ready. No demo users were created.")
    print("Create the first administrator with:")
    print("  python bootstrap_admin.py --email \"admin@company.com\" --password \"your-strong-password\"")
