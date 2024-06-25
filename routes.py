from flask import render_template, request, flash, redirect, url_for, session
from app import app
from models import User, db, UserRole, Influencer, Sponsor
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

def auth_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' in session:
            return func(*args, **kwargs)
        else:
            flash('Please login to proceed', 'warning')
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
        return redirect(url_for('index'))
    
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


@app.route('/sponsor_dashboard', methods=['GET','POST'])
@auth_required
def sponsor_dashboard():
    return render_template('sponsor_dashboard.html')