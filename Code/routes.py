from flask import render_template, request, flash, redirect, url_for, session
from app import app
from models import User, db, UserRole, Influencer, Sponsor, Campaign, AdRequest, AdRequestStatus, CampaignVisibility, Negotiation, NegotiationStatus
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from sqlalchemy import func, or_

def role_required(*roles):
    def decorator(func):
        @wraps(func)
        def inner(*args, **kwargs):
            if 'user_id' in session:
                user = User.query.get(session['user_id'])
                if user and user.role in roles:
                    return func(*args, **kwargs)
            flash('Access restricted', 'warning')
            return redirect(url_for('login'))
        return inner
    return decorator

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
            flash("User does not exist", "danger")
            return redirect(url_for('login'))

        if not check_password_hash(user.passhash, password):
            flash('Incorrect password', 'danger')
            return redirect(url_for('login'))
        
        session['user_id'] = user.id
        session['user_role'] = user.role.value

        flash('Login successful!', 'success')
        if user.role == UserRole.SPONSOR:
            return redirect(url_for('sponsor_dashboard'))
        elif user.role == UserRole.INFLUENCER:
            return redirect(url_for('influencer_dashboard'))
        elif user.role == UserRole.ADMIN:
            return redirect(url_for('admin_dashboard'))
    
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

@app.route('/admin_dashboard', methods=['GET'])
@role_required(UserRole.ADMIN)
def admin_dashboard():

    sponsor_count = Sponsor.query.count()
    influencer_count = Influencer.query.count()
    users_data = {'labels': ['Sponsors', 'Influencers'], 'data': [sponsor_count, influencer_count]}


    num_public_campaigns = Campaign.query.filter_by(visibility=CampaignVisibility.PUBLIC).count()
    num_private_campaigns = Campaign.query.filter_by(visibility=CampaignVisibility.PRIVATE).count()
    campaigns_data = {'public': num_public_campaigns, 'private': num_private_campaigns}


    current_date = datetime.now().date()
    active_campaign_count = Campaign.query.filter(Campaign.end_date >= current_date).count()
    inactive_campaign_count = Campaign.query.filter(Campaign.end_date < current_date).count()
    campaigns_status_data = {'active': active_campaign_count, 'inactive': inactive_campaign_count}

    ad_request_status_data = {
        'labels': ['Pending', 'Accepted', 'Rejected'],
        'data': [
            AdRequest.query.filter_by(status=AdRequestStatus.PENDING).count(),
            AdRequest.query.filter_by(status=AdRequestStatus.ACCEPTED).count(),
            AdRequest.query.filter_by(status=AdRequestStatus.REJECTED).count()
        ]
    }

    return render_template('admin_dashboard.html', 
                           users_data=users_data,
                           campaigns_data=campaigns_data,
                           campaigns_status_data=campaigns_status_data,
                           ad_request_status_data=ad_request_status_data)



@app.route('/sponsor_dashboard')
@role_required(UserRole.SPONSOR)
def sponsor_dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    sponsor = Sponsor.query.filter_by(user_id=user_id).first()
    if not sponsor:
        return redirect(url_for('login'))

    campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).all()
    
    num_public_campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id, visibility=CampaignVisibility.PUBLIC).count()
    num_private_campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id, visibility=CampaignVisibility.PRIVATE).count()
    campaigns_data = {'public': num_public_campaigns, 'private': num_private_campaigns}
    
    ad_requests_counts = []
    campaign_labels = []
    for campaign in campaigns:
        campaign_labels.append(campaign.name)
        ad_requests_count = AdRequest.query.filter_by(campaign_id=campaign.id).count()
        ad_requests_counts.append(ad_requests_count)
    ad_requests_data = {'labels': campaign_labels, 'data': ad_requests_counts}
    
    
    ad_request_status_data = {
        'labels': ['Pending', 'Accepted', 'Rejected'],
        'data': [
            AdRequest.query.filter(AdRequest.status == AdRequestStatus.PENDING, AdRequest.campaign_id.in_([c.id for c in campaigns])).count(),
            AdRequest.query.filter(AdRequest.status == AdRequestStatus.ACCEPTED, AdRequest.campaign_id.in_([c.id for c in campaigns])).count(),
            AdRequest.query.filter(AdRequest.status == AdRequestStatus.REJECTED, AdRequest.campaign_id.in_([c.id for c in campaigns])).count()
        ]
    }

    return render_template('sponsor_dashboard.html', 
                           sponsor=sponsor,
                           campaigns_data=campaigns_data,
                           ad_requests_data=ad_requests_data,
                           ad_request_status_data=ad_request_status_data)




@app.route('/influencer_dashboard')
@role_required(UserRole.INFLUENCER)
def influencer_dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    influencer = Influencer.query.filter_by(user_id=user_id).first()
    if not influencer:
        return redirect(url_for('login'))

    ad_requests = AdRequest.query.filter_by(influencer_id=influencer.id).all()
    campaign_ids = [ar.campaign_id for ar in ad_requests]
    campaigns = Campaign.query.filter(Campaign.id.in_(campaign_ids)).all()
    
    num_ad_requests_by_influencer = AdRequest.query.filter_by(influencer_id=influencer.id, created_by_influencer=True).count()
    num_ad_requests_by_sponsors = AdRequest.query.filter_by(influencer_id=influencer.id, created_by_influencer=False).count()
    ad_request_source_data = {'influencer': num_ad_requests_by_influencer, 'sponsor': num_ad_requests_by_sponsors}
    
    ad_requests_counts = []
    campaign_labels = []
    for campaign in campaigns:
        campaign_labels.append(campaign.name)
        ad_requests_count = AdRequest.query.filter_by(campaign_id=campaign.id, influencer_id=influencer.id).count()
        ad_requests_counts.append(ad_requests_count)
    ad_requests_data = {'labels': campaign_labels, 'data': ad_requests_counts}
    
    
    ad_request_status_data = {
        'labels': ['Pending', 'Accepted', 'Rejected'],
        'data': [
            AdRequest.query.filter(AdRequest.status == AdRequestStatus.PENDING, AdRequest.influencer_id == influencer.id).count(),
            AdRequest.query.filter(AdRequest.status == AdRequestStatus.ACCEPTED, AdRequest.influencer_id == influencer.id).count(),
            AdRequest.query.filter(AdRequest.status == AdRequestStatus.REJECTED, AdRequest.influencer_id == influencer.id).count()
        ]
    }

    return render_template('influencer_dashboard.html', 
                           influencer=influencer,
                           ad_request_source_data=ad_request_source_data,
                           ad_requests_data=ad_requests_data,
                           ad_request_status_data=ad_request_status_data)



@app.route('/sponsor_dashboard/campaigns', methods=['GET'])
@role_required(UserRole.SPONSOR)
def campaigns():
    sponsor = Sponsor.query.filter_by(user_id=session['user_id']).first()
    campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).all()
    return render_template('campaigns.html', sponsor=sponsor, campaigns=campaigns)

@app.route('/sponsor_dashboard/campaign/add', methods=['GET', 'POST'])
@role_required(UserRole.SPONSOR)
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
        return redirect(url_for('campaigns'))

    return render_template('add_campaign.html')

@app.route('/sponsor_dashboard/campaign/<int:campaign_id>/edit', methods=['GET', 'POST'])
@role_required(UserRole.SPONSOR)
def edit_campaign(campaign_id):

    #sponsor_id = session.get('user_id')
    campaign = Campaign.query.get_or_404(campaign_id)
    
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
            return redirect(url_for('edit_campaign', campaign_id=campaign_id))

        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        except ValueError:
            flash("Invalid date format", "danger")
            return redirect(url_for('edit_campaign', campaign_id=campaign_id))

        campaign.name = name
        campaign.description = description
        campaign.start_date = start_date
        campaign.end_date = end_date
        campaign.budget = budget
        campaign.visibility = visibility
        campaign.goals = goals

        db.session.commit()

        flash('Campaign updated successfully!', 'success')
        return redirect(url_for('campaign_details', campaign_id=campaign.id))

    return render_template('edit_campaign.html', campaign=campaign)


@app.route('/campaign/<int:campaign_id>/delete', methods=['POST'])
@role_required(UserRole.SPONSOR)
def delete_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    db.session.delete(campaign)
    db.session.commit()
    flash('Campaign deleted successfully!', 'success')
    return redirect(url_for('campaigns'))

@app.route('/campaign/<int:campaign_id>/details', methods=['GET'])
@role_required(UserRole.SPONSOR, UserRole.INFLUENCER)
def campaign_details(campaign_id):
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    campaign = Campaign.query.get_or_404(campaign_id)
    ad_requests = AdRequest.query.filter_by(campaign_id=campaign_id).all()
    return render_template('campaign_details.html', campaign=campaign, ad_requests=ad_requests, user=user)

@app.route('/campaign/<int:campaign_id>/ad_request/<int:ad_request_id>/details', methods=['GET'])
@role_required(UserRole.SPONSOR, UserRole.INFLUENCER)
def ad_request_details(campaign_id, ad_request_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    ad_request = AdRequest.query.filter_by(id=ad_request_id).first()
    return render_template('ad_request_details.html', campaign=campaign, ad_request=ad_request)

@app.route('/campaign/<int:campaign_id>/add_ad_request', methods=['GET', 'POST'])
@role_required(UserRole.SPONSOR, UserRole.INFLUENCER)
def add_ad_request(campaign_id):
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    if request.method == 'POST':
        if user.role == UserRole.SPONSOR:
            influencer_id = request.form.get('influencer_id')
        else:
            influencer = user.influencer[0] if user.influencer else None
            influencer_id = influencer.id if influencer else None
        
        requirements = request.form.get('requirements')
        payment_amount = request.form.get('payment_amount')
        
        if not influencer_id or not requirements or not payment_amount:
            flash("Please fill out all fields", "info")
            return redirect(url_for('add_ad_request', campaign_id=campaign_id))
        
        created_by_influencer = user.role == UserRole.INFLUENCER

        new_ad_request = AdRequest(
            campaign_id=campaign_id,
            influencer_id=influencer_id,
            requirements=requirements,
            payment_amount=payment_amount,
            created_by_influencer=created_by_influencer
        )
        db.session.add(new_ad_request)
        db.session.commit()
        
        flash('Ad request added successfully!', 'success')
        return redirect(url_for('campaign_details', campaign_id=campaign_id))
    
    campaign = Campaign.query.get_or_404(campaign_id)
    influencers = Influencer.query.all() if user.role == UserRole.SPONSOR else []
    return render_template('add_ad_request.html', campaign=campaign, influencers=influencers, user=user)


@app.route('/campaign/<int:campaign_id>/edit_ad_request/<int:ad_request_id>', methods=['GET', 'POST'])
@role_required(UserRole.SPONSOR, UserRole.INFLUENCER)
def edit_ad_request(campaign_id, ad_request_id):
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    campaign = Campaign.query.get_or_404(campaign_id)
    
    if request.method == 'POST':
        requirements = request.form.get('requirements')
        payment_amount = request.form.get('payment_amount')
        
        if not requirements or not payment_amount:
            flash("Please fill out all fields", "info")
            return redirect(url_for('edit_ad_request', campaign_id=campaign.id, ad_request_id=ad_request.id))
        
        ad_request.requirements = requirements
        ad_request.payment_amount = payment_amount
        db.session.commit()
        
        flash('Ad request updated successfully!', 'success')
        if session.get("user_role") == "sponsor":
            return redirect(url_for('campaign_details', campaign_id=campaign.id))
        else:
            return redirect(url_for('influencer_ad_requests', campaign_id=campaign.id))
    
    return render_template('edit_ad_request.html', campaign=campaign, ad_request=ad_request)

@app.route('/campaign/<int:campaign_id>/delete_ad_request/<int:ad_request_id>', methods=['POST'])
@role_required(UserRole.SPONSOR, UserRole.INFLUENCER)
def delete_ad_request(campaign_id, ad_request_id):
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    campaign = Campaign.query.get_or_404(campaign_id)
    db.session.delete(ad_request)
    db.session.commit()
    flash('Ad request deleted successfully!', 'success')
    if session.get("user_role") == "sponsor":
        return redirect(url_for('campaign_details', campaign_id=campaign.id))
    else:
        return redirect(url_for('influencer_ad_requests', campaign_id=campaign.id))


@app.route('/ad_request/<int:ad_request_id>/accept', methods=['POST'])
@role_required(UserRole.SPONSOR, UserRole.INFLUENCER)
def accept_ad_request(ad_request_id):
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    ad_request.status = AdRequestStatus.ACCEPTED
    db.session.commit()
    flash('Ad request accepted successfully!', 'success')
    if session.get("user_role") == "sponsor":
        return redirect(url_for('campaign_details', campaign_id=ad_request.campaign.id))
    else:
        return redirect(url_for('influencer_ad_requests', campaign_id=ad_request.campaign.id))

@app.route('/ad_request/<int:ad_request_id>/reject', methods=['POST'])
@role_required(UserRole.SPONSOR, UserRole.INFLUENCER)
def reject_ad_request(ad_request_id):
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    ad_request.status = AdRequestStatus.REJECTED
    db.session.commit()
    flash('Ad request rejected successfully!', 'success')
    if session.get("user_role") == "sponsor":
        return redirect(url_for('campaign_details', campaign_id=ad_request.campaign.id))
    else:
        return redirect(url_for('influencer_ad_requests', campaign_id=ad_request.campaign.id))


@app.route('/ad_request/negotiation/<int:ad_request_id>', methods=['GET', 'POST'])
@role_required(UserRole.SPONSOR, UserRole.INFLUENCER)
def negotiation(ad_request_id):
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    user_id = session.get('user_id')
    role = session.get('user_role')

    if role == 'influencer':
        influencer = Influencer.query.filter_by(user_id=user_id).first()
        is_receiver = not ad_request.created_by_influencer and ad_request.influencer_id == influencer.id
    else:
        sponsor = Sponsor.query.filter_by(user_id=user_id).first()
        is_receiver = ad_request.created_by_influencer and ad_request.campaign.sponsor.id == sponsor.id

    if request.method == 'POST' and is_receiver:
        active_negotiation = Negotiation.query.filter_by(ad_request_id=ad_request.id, status=NegotiationStatus.PENDING).first()
        if active_negotiation:
            flash('There is already an active negotiation.', 'warning')
        else:
            proposed_price = request.form.get('proposed_price')
            if proposed_price:
                negotiation = Negotiation(
                    ad_request_id=ad_request.id,
                    sender_id=user_id,
                    receiver_id=ad_request.campaign.sponsor.user_id if ad_request.created_by_influencer else ad_request.influencer.user_id,
                    proposed_price=float(proposed_price)
                )
                db.session.add(negotiation)
                db.session.commit()
                flash('Proposal sent!', 'success')
                return redirect(url_for('negotiation', ad_request_id=ad_request.id))

    negotiations = Negotiation.query.filter_by(ad_request_id=ad_request.id).order_by(Negotiation.timestamp.desc()).all()

    return render_template('negotiation.html', ad_request=ad_request, negotiations=negotiations, is_receiver=is_receiver)

@app.route('/negotiation/respond/<int:negotiation_id>', methods=['POST'])
@role_required(UserRole.SPONSOR, UserRole.INFLUENCER)
def respond_negotiation(negotiation_id):
    negotiation = Negotiation.query.get_or_404(negotiation_id)
    ad_request = negotiation.ad_request
    user_id = session.get('user_id')
    role = session.get('user_role')

    if role == 'influencer':
        influencer = Influencer.query.filter_by(user_id=user_id).first()
        is_initiator = ad_request.created_by_influencer and ad_request.influencer_id == influencer.id
    else:
        sponsor = Sponsor.query.filter_by(user_id=user_id).first()
        is_initiator = not ad_request.created_by_influencer and ad_request.campaign.sponsor.id == sponsor.id

    if not is_initiator:
        flash('You do not have permission to respond to this negotiation.', 'danger')
        return redirect(url_for('negotiation', ad_request_id=ad_request.id))

    response = request.form.get('response')
    if response == 'accept':
        negotiation.status = NegotiationStatus.ACCEPTED
        ad_request.status = AdRequestStatus.ACCEPTED
        ad_request.payment_amount = negotiation.proposed_price
    elif response == 'reject':
        negotiation.status = NegotiationStatus.REJECTED
    db.session.commit()
    flash(f'Proposal has been {response}ed.', 'success')
    return redirect(url_for('negotiation', ad_request_id=ad_request.id))




@app.route('/sponsor_dashboard/find_influencer', methods=['GET', 'POST'])
@role_required(UserRole.SPONSOR)
def find_influencer():
    influencers = []
    if request.method == 'POST':
        search = request.form.get('search')
        
        query = Influencer.query
        if search:
            query = query.filter(or_(Influencer.niche.ilike(search), Influencer.reach.ilike(search)))
        
        influencers = query.all()
    
    return render_template('find_influencer.html', influencers=influencers)

@app.route('/influencer_dashboard/find_campaign', methods=['GET', 'POST'])
@role_required(UserRole.INFLUENCER)
def find_campaign():
    if request.method == 'POST':
        min_budget = request.form.get('min_budget', type=float, default=0)
        max_budget = request.form.get('max_budget', type=float, default=float('inf'))
        public_campaigns = Campaign.query.filter(
            Campaign.visibility == CampaignVisibility.PUBLIC,
            Campaign.budget >= min_budget,
            Campaign.budget <= max_budget
        ).all()
    else:
        public_campaigns = Campaign.query.filter_by(visibility=CampaignVisibility.PUBLIC).all()
    return render_template('find_campaign.html', campaigns=public_campaigns)

@app.route('/influencer_dashboard/influencer_ad_requests', methods=['GET'])
@role_required(UserRole.INFLUENCER)
def influencer_ad_requests():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    ad_requests = AdRequest.query.filter(
        AdRequest.influencer_id == user.influencer[0].id).join(Campaign).join(Sponsor).all()
    
    return render_template('influencer_ad_requests.html', ad_requests=ad_requests, user=user)

@app.route('/admin_dashboard/campaigns', methods=['GET'])
@role_required(UserRole.ADMIN)
def admin_campaigns():
    campaigns = Campaign.query.all()
    return render_template('admin_campaigns.html', campaigns=campaigns)

@app.route('/admin_dashboard/ad_requests', methods=['GET'])
@role_required(UserRole.ADMIN)
def admin_ad_requests():
    ad_requests = AdRequest.query.all()
    return render_template('admin_ad_requests.html', ad_requests=ad_requests)

@app.route('/admin_dashboard/users', methods=['GET'])
@role_required(UserRole.ADMIN)
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin_dashboard/campaigns/<int:campaign_id>/flag_campaign')
@role_required(UserRole.ADMIN)
def flag_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    campaign.flagged = not campaign.flagged
    db.session.commit()
    flash('Campaign flagged successfully!', 'success')
    return redirect(url_for('admin_campaigns'))

@app.route('/admin_dashboard/users/<int:user_id>/flag_user')
@role_required(UserRole.ADMIN)
def flag_user(user_id):
    user = User.query.get_or_404(user_id)
    user.flagged = not user.flagged
    db.session.commit()
    flash('User flagged successfully!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/change_password', methods=['GET', 'POST'])
@role_required(UserRole.SPONSOR, UserRole.INFLUENCER, UserRole.ADMIN)
def change_password():
    user_id = session.get('user_id')
    if not user_id:
        flash('You need to be logged in to change your password.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(user_id)

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not check_password_hash(user.passhash, current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('change_password'))

        user.passhash = generate_password_hash(new_password)
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('sponsor_dashboard'))

    return render_template('change_password.html')



@app.route('/logout', methods=['GET', 'POST'])
@role_required(UserRole.SPONSOR, UserRole.INFLUENCER, UserRole.ADMIN)
def logout():
    session.pop('user_id')
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))


