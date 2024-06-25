from app import app
from flask_sqlalchemy import SQLAlchemy
from enum import Enum
from sqlalchemy import Enum as SQLAlchemyEnum
from werkzeug.security import generate_password_hash

db = SQLAlchemy(app)

class UserRole(Enum):
    ADMIN = "admin"
    SPONSOR = "sponsor"
    INFLUENCER = "influencer"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True)
    passhash = db.Column(db.String(256), nullable=False)
    role = db.Column(SQLAlchemyEnum(UserRole), nullable=False)

class Sponsor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    company_name = db.Column(db.String(128), nullable=True)
    industry = db.Column(db.String(128), nullable=True)
    budget = db.Column(db.Float, nullable=True)
    user = db.relationship('User', backref='sponsor', uselist=False)

class Influencer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(128), nullable=True)
    category = db.Column(db.String(128), nullable=True)
    niche = db.Column(db.String(128), nullable=True)
    reach = db.Column(db.Integer, nullable=True)
    user = db.relationship('User', backref='influencer', uselist=False)


def create_admin():
    admin = User.query.filter_by(role=UserRole.ADMIN).first()
    if admin is None:
        admin_username = "admin"
        admin_password = "Admin@123"
        password_hash = generate_password_hash(admin_password)
        admin = User(username=admin_username, passhash=password_hash, role=UserRole.ADMIN)
        db.session.add(admin)
        db.session.commit()

with app.app_context():
    db.create_all()
    create_admin()