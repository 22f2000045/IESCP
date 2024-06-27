from app import app
from flask_sqlalchemy import SQLAlchemy
from enum import Enum
from sqlalchemy import Enum as SQLAlchemyEnum
from werkzeug.security import generate_password_hash
from datetime import datetime

db = SQLAlchemy(app)

class UserRole(Enum):
    ADMIN = "admin"
    SPONSOR = "sponsor"
    INFLUENCER = "influencer"

class CampaignVisibility(Enum):
    PUBLIC = "public"
    PRIVATE = "private"

class AdRequestStatus(Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    passhash = db.Column(db.String(256), nullable=False)
    role = db.Column(SQLAlchemyEnum(UserRole), nullable=False)

class Sponsor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_name = db.Column(db.String(128), nullable=True)
    industry = db.Column(db.String(128), nullable=True)
    budget = db.Column(db.Float, nullable=True)
    user = db.relationship('User', backref='sponsor', uselist=False)

class Influencer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(128), nullable=True)
    category = db.Column(db.String(128), nullable=True)
    niche = db.Column(db.String(128), nullable=True)
    reach = db.Column(db.Integer, nullable=True)
    user = db.relationship('User', backref='influencer', uselist=False)

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('sponsor.id'), nullable=False)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=True)
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)
    budget = db.Column(db.Float, nullable=False)
    visibility = db.Column(SQLAlchemyEnum(CampaignVisibility), nullable=False)
    goals = db.Column(db.Text, nullable=True)
    
    sponsor = db.relationship('Sponsor', backref='campaigns')

    @property
    def completion_percentage(self):
        if not self.start_date or not self.end_date:
            return 0
        total_duration = (self.end_date - self.start_date).days
        elapsed_duration = (datetime.now().date() - self.start_date).days
        if elapsed_duration < 0:
            return 0 
        return min(100, (elapsed_duration / total_duration) * 100)

class AdRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    influencer_id = db.Column(db.Integer, db.ForeignKey('influencer.id'), nullable=False)
    messages = db.Column(db.Text, nullable=True)
    requirements = db.Column(db.Text, nullable=False)
    payment_amount = db.Column(db.Float, nullable=False)
    status = db.Column(SQLAlchemyEnum(AdRequestStatus), nullable=False, default=AdRequestStatus.PENDING)

    campaign = db.relationship('Campaign', backref='ad_requests')
    influencer = db.relationship('Influencer', backref='ad_requests')


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