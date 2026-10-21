# Phish-Hunter-k4 data store

`phishhunter.db` is the single SQLAlchemy/SQLite persistence file used by the local application.

The distributed database is **schema-only**: it contains the application tables but no administrator, analyst or demo account. Create the first administrator explicitly with:

```powershell
python .\bootstrap_admin.py --email "admin@company.com" --password "Use-A-Strong-Password-Here" --organization "K4 Security Operations"
```

Passwords are stored as Argon2 hashes. User activity, authentication events and account lifecycle actions are stored in `user_activity` for the administrator analytics pages.
