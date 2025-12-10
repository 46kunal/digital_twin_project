# create_admin.py
from app import create_app
from models import db, User, ROLE_ADMIN

def create_admin(username="admin", password="admin123", email=None):
    app = create_app()
    with app.app_context():
        db.create_all()
        if User.query.filter_by(username=username).first():
            print("User already exists")
            return
        u = User(username=username, email=email, role=ROLE_ADMIN)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        print("Created admin:", username)

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--username", default="admin")
    p.add_argument("--password", default="admin123")
    p.add_argument("--email", default=None)
    args = p.parse_args()
    create_admin(args.username, args.password, args.email)
