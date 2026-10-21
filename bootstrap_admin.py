from __future__ import annotations

import argparse
from sqlalchemy import text
from phishhunter.db.database import SessionLocal
from phishhunter.models import Tenant, User, UserProfile, UserControl, AuditEvent, UserActivity
from phishhunter.security.passwords import hash_password


def main() -> None:
    parser = argparse.ArgumentParser(description="Create or reset a K4 administrator identity")
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--organization", default="K4 Security Operations")
    # The bootstrap command creates or resets the named administrator identity.
    # Additional administrators may also be granted from the admin control plane.
    parser.add_argument("--rotate-existing", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    email = args.email.strip().lower()
    username = email.split("@", 1)[0][:64]
    if len(args.password) < 8:
        raise SystemExit("Administrator password must be at least 8 characters")
    with SessionLocal() as db:
        # Repair legacy databases before identity provisioning.  A failed older
        # bootstrap could leave an orphan user_controls row whose unique
        # user_id prevents the next administrator from being created.
        db.execute(text(
            "DELETE FROM user_controls WHERE user_id NOT IN (SELECT id FROM users)"
        ))
        db.execute(text(
            "DELETE FROM user_profiles WHERE user_id NOT IN (SELECT id FROM users)"
        ))
        user = db.query(User).filter_by(email=email).first()
        if user:
            tenant = db.get(Tenant, user.tenant_id)
            user.is_admin = True
            if not user.username:
                user.username = username
            user.password_hash = hash_password(args.password)
            control = db.query(UserControl).filter_by(user_id=user.id).first()
            if not control:
                control = UserControl(user_id=user.id)
                db.add(control)
            control.disabled = False
            control.failed_logins = 0
            profile = db.query(UserProfile).filter_by(user_id=user.id).first()
            if not profile:
                profile = UserProfile(user_id=user.id, display_name=email.split("@")[0], job_title="Administrator")
                db.add(profile)
            else:
                profile.job_title = "Administrator"
            if tenant and args.organization.strip():
                # Keep the existing tenant ID so scans/cases/reports remain
                # attached to the same workspace when an analyst is promoted
                # through the terminal bootstrap.
                tenant.name = args.organization.strip()
        else:
            tenant = db.query(Tenant).filter_by(name=args.organization.strip()).first()
            if not tenant:
                tenant = Tenant(name=args.organization.strip())
                db.add(tenant)
                db.flush()
            user = User(tenant_id=tenant.id, username=username, email=email, password_hash=hash_password(args.password), is_admin=True)
            db.add(user)
            db.flush()
            db.add(UserProfile(user_id=user.id, display_name=email.split("@")[0], job_title="Administrator"))
            db.add(UserControl(user_id=user.id))

        db.add(AuditEvent(
            tenant_id=user.tenant_id,
            action="admin.bootstrap",
            detail=f"Bootstrap administrator {user.email} configured",
        ))
        db.add(UserActivity(
            user_id=user.id,
            actor_user_id=user.id,
            event_type="account",
            action="account.bootstrap",
            detail="Administrator identity configured by terminal bootstrap",
            metadata_json={"organization": args.organization.strip()},
        ))
        db.commit()
        print(f"Administrator ready: {user.email} (tenant={user.tenant_id})")
        print("Admin console: http://127.0.0.1:8000/admin")
        print("Main website: http://127.0.0.1:8000")


if __name__ == "__main__":
    main()
