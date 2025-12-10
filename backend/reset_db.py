from app import create_app
from models import db

app, _ = create_app()

with app.app_context():
    db.drop_all()
    db.create_all()
    print("DB reset done")
