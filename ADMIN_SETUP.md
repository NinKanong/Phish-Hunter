# Phish-Hunter-k4 Administration

## Main application
- Main website: http://127.0.0.1:8000
- Normal sign-in: http://127.0.0.1:8000/login
- Registration: http://127.0.0.1:8000/register

## Administrator control plane
- Admin UI: http://127.0.0.1:8000/admin
- Admin sign-in: http://127.0.0.1:8000/admin/login
- Health: http://127.0.0.1:8000/admin/health

## First administrator
No placeholder or demo identities are created during startup or installation. Create the administrator explicitly:

```powershell
python .\bootstrap_admin.py --email "admin@company.com" --password "Use-A-Strong-Password-Here" --organization "K4 Security Operations"
python .\run.py
```

The supplied password is converted to an Argon2 hash before it is stored. The plaintext password is never written to SQL. Running the command again for the same email resets that administrator's password and re-enables the account.

## Roles and permissions
- **Analyst** — normal investigation workspace and saved analysis.
- **Administrator** — Analyst access plus the control plane: users, permissions, password resets, account status, deletion, organization management, audit and analytics.

Administrators can create additional administrators from the Users & Access page. At least one administrator must remain active, and an administrator cannot disable or delete their own account.

## User management
The Users & Access page supports: create user, assign Analyst/Administrator role, disable/enable access, reset forgotten passwords, edit profile, permanently delete identities, and open a per-user activity dashboard. Clicking a user shows a 30-day login/activity graph and a detailed timeline.

## Persistence
The default SQL database is:
`sqlite:///./data/phishhunter.db`

The SQLite path is resolved from the project directory, so starting `run.py` from another working directory still reaches the same database. The distributable project contains a clean schema-only database with zero users.

All identity state is database-backed. The `user_activity` table stores login, account lifecycle and analysis activity metadata. Browser localStorage is used only for the optional "remember email" convenience; it is not the source of authentication state.

## No auto-created users
`python -m phishhunter.seed` now initializes only the database schema. It does not create a demo user. Installation scripts may call it safely; the administrator must still be bootstrapped explicitly.

## V26 database safety

V26 automatically repairs legacy orphan identity-control rows during SQLite initialization and the bootstrap command. The distributable package intentionally does not contain a mutable `data/phishhunter.db`; the schema is created on first start.
