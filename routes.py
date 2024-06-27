from flask import render_template, request, flash, redirect, url_for, session
from app import app
from models import User, db, UserRole, Influencer, Sponsor, Campaign, AdRequest
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from sqlalchemy.orm.exc import NoResultFound

def sponsor_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user and user.role == UserRole.SPONSOR:
                return func(*args, **kwargs)
        flash('Access restricted to sponsors only', 'warning')
        return redirect(url_for('login'))
    return inner

def influencer_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user and user.role == UserRole.INFLUENCER:
                return func(*args, **kwargs)
        flash('Access restricted to influencers only', 'warning')
        return redirect(url_for('login'))
    return inner

def admin_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user and user.role == UserRole.ADMIN:
                return func(*args, **kwargs)
        flash('Access restricted to admins only', 'warning')
        return redirect(url_for('login'))
    return inner

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash("Please fill out all fields", "info")
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash("User does not exists", "danger")
            return redirect(url_for('login'))

        if not check_password_hash(user.passhash, password):
            flash('Incorrect password', 'danger')
            return redirect(url_for('login'))
        
        session['user_id']=user.id

        flash('Login successful!', 'success')
        if user.role == UserRole.SPONSOR:
            return redirect(url_for('sponsor_dashboard'))
        elif user.role == UserRole.INFLUENCER:
            return redirect(url_for('influencer_dashboard'))
    
    return render_template('login.html')

@app.route('/sponsor_register', methods=['GET', 'POST'])
def sponsor_register():
    if request.method == 'POST':
        company_name = request.form.get('company_name')
        username = request.form.get('username')
        industry = request.form.get('industry')
        budget = request.form.get('budget')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password or not confirm_password:
            flash("Please fill out all fields", "info")
            return redirect(url_for('sponsor_register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('sponsor_register'))
        
        user = User.query.filter_by(username=username).first()
        
        if user:
            flash('Username already exists', 'warning')
            return redirect(url_for('sponsor_register'))
        
        password_hash = generate_password_hash(password)

        new_user = User(username=username, passhash=password_hash, role=UserRole.SPONSOR)
        db.session.add(new_user)
        db.session.commit()
        
        new_sponsor = Sponsor(user_id=new_user.id, company_name=company_name, industry=industry, budget=budget)
        db.session.add(new_sponsor)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('sponsor_register.html')

@app.route('/influencer_register', methods=['GET', 'POST'])
def influencer_register():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        category = request.form.get('category')
        niche = request.form.get('niche')
        reach = request.form.get('reach')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password or not confirm_password:
            flash("Please fill out all fields", "info")
            return redirect(url_for('influencer_register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('influencer_register'))
        
        user = User.query.filter_by(username=username).first()
        
        if user:
            flash('Username already exists', 'warning')
            return redirect(url_for('influencer_register'))
        
        password_hash = generate_password_hash(password)

        new_user = User(username=username, passhash=password_hash, role=UserRole.INFLUENCER)
        db.session.add(new_user)
        db.session.commit()
        
        new_influencer = Influencer(user_id=new_user.id, name=name, category=category, niche=niche, reach=reach)
        db.session.add(new_influencer)
        db.session.commit()

        flash('Registration successful! Please login', 'success')
        return redirect(url_for('login'))
    
    return render_template('influencer_register.html')


@app.route('/sponsor_dashboard', methods=['GET', 'POST'])
@sponsor_required
def sponsor_dashboard():
    user_id = session.get('user_id')
    sponsor = Sponsor.query.filter_by(user_id=user_id).first()
    campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).all()
    ad_requests = AdRequest.query.filter(AdRequest.campaign_id.in_([campaign.id for campaign in campaigns])).all()

    return render_template('sponsor_dashboard.html', sponsor=sponsor, campaigns=campaigns, ad_requests=ad_requests)



@app.route('/add_campaign', methods=['GET', 'POST'])
@sponsor_required
def add_campaign():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        budget = request.form.get('budget')
        visibility = request.form.get('visibility')
        goals = request.form.get('goals')

        if not name or not start_date or not end_date or not budget or not visibility:
            flash("Please fill out all required fields", "info")
            return redirect(url_for('add_campaign'))

        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        except ValueError:
            flash("Invalid date format", "danger")
            return redirect(url_for('add_campaign'))

        sponsor_id = session.get('user_id')
        sponsor = Sponsor.query.filter_by(user_id=sponsor_id).first()

        new_campaign = Campaign(
            sponsor_id=sponsor.id,
            name=name,
            description=description,
            start_date=start_date,
            end_date=end_date,
            budget=budget,
            visibility=visibility,
            goals=goals
        )

        db.session.add(new_campaign)
        db.session.commit()

        flash('Campaign created successfully!', 'success')
        return redirect(url_for('sponsor_dashboard'))

    return render_template('add_campaign.html')


@app.route('/campaign_details/<int:campaign_id>', methods=['GET'])
@sponsor_required
def campaign_details(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    ad_requests = AdRequest.query.filter_by(campaign_id=campaign_id).all()
    return render_template('campaign_details.html', campaign=campaign, ad_requests=ad_requests)


@app.route('/add_ad_request/<int:campaign_id>', methods=['GET', 'POST'])
@sponsor_required
def add_ad_request(campaign_id):
    if request.method == 'POST':
        influencer_id = request.form.get('influencer_id')
        requirements = request.form.get('requirements')
        payment_amount = request.form.get('payment_amount')
        
        if not influencer_id or not requirements or not payment_amount:
            flash("Please fill out all fields", "info")
            return redirect(url_for('add_ad_request', campaign_id=campaign_id))
        
        new_ad_request = AdRequest(
            campaign_id=campaign_id,
            influencer_id=influencer_id,
            requirements=requirements,
            payment_amount=payment_amount
        )
        db.session.add(new_ad_request)
        db.session.commit()
        
        flash('Ad request added successfully!', 'success')
        return redirect(url_for('campaign_details', campaign_id=campaign_id))
    
    campaign = Campaign.query.get_or_404(campaign_id)
    influencers = Influencer.query.all()  # Retrieve all influencers for the dropdown
    return render_template('add_ad_request.html', campaign=campaign, influencers=influencers)
