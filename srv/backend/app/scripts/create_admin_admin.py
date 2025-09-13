from app import models, crud, auth
from app.models import AdminCreate


def main() -> None:
    db = models.SessionLocal()
    try:
        username = "admin"
        password = "admin"

        admin = crud.get_admin_by_username(db, username)
        if admin:
            admin.hashed_password = auth.get_password_hash(password)
            db.add(admin)
            db.commit()
            print("Password reset for existing admin user 'admin'.")
        else:
            crud.create_admin(db, AdminCreate(username=username, password=password))
            print("Admin user 'admin' created with password 'admin'.")
    finally:
        db.close()


if __name__ == "__main__":
    main()