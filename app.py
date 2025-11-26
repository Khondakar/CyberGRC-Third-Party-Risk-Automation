import os
import uuid
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.exceptions import abort
from models import db, User, Questionnaire, QuestionnaireTemplate, Question, ScanReport, RiskAssessment, LogEntry
from models import QuestionnaireQuestion, QuestionnaireResponse
from forms import RegistrationForm, LoginForm, QuestionnaireForm, ScanForm, ThirdPartyResponseForm
import secrets
import string

# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///riskauto.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Security configurations
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize database and templates
def init_db():
    """Initialize database and populate with default data"""
    db.create_all()
    
    # Create default questionnaire templates if they don't exist
    if not QuestionnaireTemplate.query.first():
        create_default_templates()

def create_default_templates():
    """Create default security questionnaire templates"""
    templates_data = [
        {
            'name': 'Standard Security Assessment',
            'description': 'Comprehensive security questionnaire covering essential security practices',
            'template_type': 'standard',
            'questions': [
                {'question': 'Do you have a documented information security policy?', 'category': 'Governance', 'weight': 'high'},
                {'question': 'Is multi-factor authentication (MFA) enforced for all users?', 'category': 'Access Control', 'weight': 'critical'},
                {'question': 'Do you perform regular security awareness training for employees?', 'category': 'Training', 'weight': 'medium'},
                {'question': 'Are security patches applied within 30 days of release?', 'category': 'Patch Management', 'weight': 'high'},
                {'question': 'Do you encrypt data at rest and in transit?', 'category': 'Data Protection', 'weight': 'critical'},
                {'question': 'Do you have an incident response plan?', 'category': 'Incident Management', 'weight': 'high'},
                {'question': 'Are regular security audits conducted?', 'category': 'Compliance', 'weight': 'medium'},
                {'question': 'Do you maintain data backups with tested recovery procedures?', 'category': 'Business Continuity', 'weight': 'high'}
            ]
        },
        {
            'name': 'Cloud Security Assessment',
            'description': 'Focused on cloud infrastructure security and best practices',
            'template_type': 'cloud',
            'questions': [
                {'question': 'Do you use a major cloud service provider (AWS, Azure, GCP)?', 'category': 'Infrastructure', 'weight': 'medium'},
                {'question': 'Is cloud data encrypted using strong encryption standards?', 'category': 'Data Protection', 'weight': 'critical'},
                {'question': 'Do you implement network segmentation in your cloud environment?', 'category': 'Network Security', 'weight': 'high'},
                {'question': 'Are cloud access logs monitored and reviewed regularly?', 'category': 'Monitoring', 'weight': 'high'},
                {'question': 'Do you have DDoS protection implemented?', 'category': 'Availability', 'weight': 'medium'},
                {'question': 'Is your cloud infrastructure compliant with industry standards (ISO 27001, SOC 2)?', 'category': 'Compliance', 'weight': 'high'},
                {'question': 'Do you use infrastructure as code with version control?', 'category': 'DevSecOps', 'weight': 'medium'}
            ]
        },
        {
            'name': 'GDPR Compliance',
            'description': 'GDPR-specific privacy and data protection assessment',
            'template_type': 'gdpr',
            'questions': [
                {'question': 'Do you have a Data Protection Officer (DPO) appointed?', 'category': 'Governance', 'weight': 'high'},
                {'question': 'Can data subjects request deletion of their personal data?', 'category': 'Rights Management', 'weight': 'critical'},
                {'question': 'Do you maintain a data processing inventory?', 'category': 'Documentation', 'weight': 'high'},
                {'question': 'Are data breach notification procedures in place?', 'category': 'Incident Response', 'weight': 'critical'},
                {'question': 'Do you conduct Data Protection Impact Assessments (DPIA)?', 'category': 'Risk Assessment', 'weight': 'high'},
                {'question': 'Is consent obtained for data processing activities?', 'category': 'Consent Management', 'weight': 'critical'}
            ]
        }
    ]
    
    for template_data in templates_data:
        template = QuestionnaireTemplate(
            name=template_data['name'],
            description=template_data['description'],
            template_type=template_data['template_type']
        )
        db.session.add(template)
        db.session.flush()  # Get the template ID
        
        for q_data in template_data['questions']:
            question = Question(
                template_id=template.id,
                question_text=q_data['question'],
                category=q_data['category'],
                weight=q_data['weight']
            )
            db.session.add(question)
    
    db.session.commit()

# Security logging helper
def log_security_event(user_id, action, resource=None, resource_id=None, success=True, details=None):
    """Log security events for audit trail"""
    try:
        LogEntry.log_action(
            user_id=user_id,
            action=action,
            resource=resource,
            resource_id=resource_id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string if request.user_agent else None,
            success=success,
            details=details
        )
    except Exception as e:
        app.logger.error(f"Failed to log security event: {e}")

# Routes

@app.route('/')
def index():
    """Landing page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            email=form.email.data.lower(),
            company_name=form.company_name.data.strip(),
            full_name=form.full_name.data.strip()
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        log_security_event(user.id, 'user_registration', details=f"User {user.email} registered")
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login with security measures"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        
        if user and not user.is_active:
            flash('Account is deactivated. Please contact support.', 'error')
            log_security_event(None, 'login_attempt_deactivated', user.email, success=False)
            return redirect(url_for('login'))
        
        if user and user.check_password(form.password.data):
            if user.is_account_locked():
                flash('Account is temporarily locked due to multiple failed login attempts.', 'error')
                log_security_event(user.id, 'login_attempt_locked', success=False)
                return redirect(url_for('login'))
            
            login_user(user, remember=form.remember.data)
            user.reset_failed_attempts()
            db.session.commit()
            
            log_security_event(user.id, 'login_success', details=f"User {user.email} logged in")
            flash('Welcome back!', 'success')
            return redirect(url_for('dashboard'))
        else:
            if user:
                user.increment_failed_attempts()
                db.session.commit()
                log_security_event(user.id, 'login_failed', success=False)
            
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    log_security_event(current_user.id, 'logout', details=f"User {current_user.email} logged out")
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    # Get user data for dashboard
    user_questionnaires = Questionnaire.query.filter_by(user_id=current_user.id).all()
    user_scans = ScanReport.query.filter_by(user_id=current_user.id).all()
    user_assessments = RiskAssessment.query.filter_by(user_id=current_user.id).all()
    
    # Calculate statistics
    stats = {
        'total_questionnaires': len(user_questionnaires),
        'completed_questionnaires': len([q for q in user_questionnaires if q.status == 'Completed']),
        'total_scans': len(user_scans),
        'total_assessments': len(user_assessments)
    }
    
    return render_template('dashboard.html', 
                         stats=stats,
                         questionnaires=user_questionnaires[:5],  # Recent 5
                         scans=user_scans[:5],
                         assessments=user_assessments[:5])

# Passive Scanning Routes

@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    """Initiate security scan"""
    form = ScanForm()
    if form.validate_on_submit():
        # Create scan report
        scan_report = ScanReport(
            user_id=current_user.id,
            target=form.target.data.strip(),
            scan_type=form.scan_type.data,
            status='pending'
        )
        db.session.add(scan_report)
        db.session.commit()
        
        log_security_event(current_user.id, 'scan_initiated', 'scan', str(scan_report.id), 
                          details=f"Scan started for {scan_report.target}")
        
        # Simulate scan process (in real implementation, this would be async)
        scan_findings = simulate_scan(form.target.data.strip(), form.scan_type.data)
        
        # Update scan with results
        scan_report.status = 'completed'
        scan_report.progress = 100
        scan_report.completion_date = datetime.utcnow()
        scan_report.set_findings(scan_findings)
        db.session.commit()
        
        flash(f'Scan completed for {scan_report.target}', 'success')
        return redirect(url_for('view_scan', scan_id=scan_report.id))
    
    # Get recent scans for the user
    recent_scans = ScanReport.query.filter_by(user_id=current_user.id).order_by(ScanReport.scan_date.desc()).limit(5).all()
    
    return render_template('scan.html', form=form, scans=recent_scans)

def simulate_scan(target, scan_type):
    """Simulate security scan results (replace with real scanning logic)"""
    findings = {
        'target': target,
        'scan_type': scan_type,
        'timestamp': datetime.utcnow().isoformat(),
        'findings': []
    }
    
    # Port scan results
    if scan_type in ['comprehensive', 'ports']:
        findings['findings'].append({
            'category': 'Open Ports',
            'severity': 'Medium',
            'details': 'Common ports detected: 80 (HTTP), 443 (HTTPS), 22 (SSH)',
            'recommendation': 'Ensure only necessary ports are exposed. Consider restricting SSH access.'
        })
    
    # SSL/TLS results
    if scan_type in ['comprehensive', 'ssl']:
        findings['findings'].append({
            'category': 'SSL/TLS Certificate',
            'severity': 'Low',
            'details': 'Valid SSL certificate found. Strong cipher suites in use.',
            'recommendation': 'Certificate appears secure. Monitor for expiration.'
        })
    
    # DNS results
    if scan_type in ['comprehensive', 'dns']:
        findings['findings'].append({
            'category': 'DNS Configuration',
            'severity': 'Low',
            'details': 'DNS records configured. DNSSEC not detected.',
            'recommendation': 'Consider implementing DNSSEC for additional security.'
        })
    
    # Security headers (always check)
    findings['findings'].append({
        'category': 'Security Headers',
        'severity': 'High',
        'details': 'Missing or weak security headers detected.',
        'recommendation': 'Implement security headers: X-Frame-Options, Content-Security-Policy, X-XSS-Protection.'
    })
    
    return findings

@app.route('/scan/<int:scan_id>')
@login_required
def view_scan(scan_id):
    """View scan results"""
    scan = ScanReport.query.filter_by(id=scan_id, user_id=current_user.id).first()
    if not scan:
        abort(404)
    
    findings = scan.get_findings()
    return render_template('scan_result.html', scan=scan, findings=findings)

# Questionnaire Routes

@app.route('/questionnaires', methods=['GET', 'POST'])
@login_required
def questionnaires():
    """Create and manage questionnaires"""
    form = QuestionnaireForm()
    if form.validate_on_submit():
        # Generate share token
        share_token = str(uuid.uuid4())
        
        # Create questionnaire
        questionnaire = Questionnaire(
            user_id=current_user.id,
            name=form.name.data.strip(),
            third_party_name=form.third_party_name.data.strip(),
            third_party_email=form.third_party_email.data.strip(),
            share_token=share_token
        )
        
        db.session.add(questionnaire)
        db.session.flush()
        
        # Get template questions
        template = QuestionnaireTemplate.query.get(form.template.data)
        if template:
            for template_q in template.questions:
                q = QuestionnaireQuestion(
                    questionnaire_id=questionnaire.id,
                    question_text=template_q.question_text,
                    category=template_q.category,
                    weight=template_q.weight
                )
                db.session.add(q)
        
        db.session.commit()
        
        log_security_event(current_user.id, 'questionnaire_created', 'questionnaire', str(questionnaire.id),
                          details=f"Created questionnaire for {questionnaire.third_party_name}")
        
        # Generate shareable link
        share_url = url_for('third_party_questionnaire', token=share_token, _external=True)
        
        flash(f'Questionnaire created and sent to {questionnaire.third_party_email}', 'success')
        return redirect(url_for('questionnaire_detail', questionnaire_id=questionnaire.id))
    
    user_questionnaires = Questionnaire.query.filter_by(user_id=current_user.id).order_by(Questionnaire.sent_date.desc()).all()
    return render_template('questionnaires.html', form=form, questionnaires=user_questionnaires)

@app.route('/questionnaire/<int:questionnaire_id>')
@login_required
def questionnaire_detail(questionnaire_id):
    """View questionnaire details"""
    questionnaire = Questionnaire.query.filter_by(id=questionnaire_id, user_id=current_user.id).first()
    if not questionnaire:
        abort(404)
    
    return render_template('questionnaire_detail.html', questionnaire=questionnaire)

@app.route('/q/<token>')
def third_party_questionnaire(token):
    """Public questionnaire response page"""
    questionnaire = Questionnaire.query.filter_by(share_token=token).first()
    if not questionnaire:
        flash('Invalid questionnaire link.', 'error')
        return redirect(url_for('index'))
    
    if questionnaire.status == 'Completed':
        flash('This questionnaire has already been completed.', 'info')
        return redirect(url_for('index'))
    
    return render_template('third_party_questionnaire.html', questionnaire=questionnaire)

@app.route('/q/<token>/submit', methods=['POST'])
def submit_questionnaire_response(token):
    """Submit third-party questionnaire responses"""
    questionnaire = Questionnaire.query.filter_by(share_token=token).first()
    if not questionnaire:
        flash('Invalid questionnaire link.', 'error')
        return redirect(url_for('index'))
    
    if questionnaire.status == 'Completed':
        flash('This questionnaire has already been completed.', 'info')
        return redirect(url_for('index'))
    
    # Process responses
    total_yes = total_no = total_partial = total_na = 0
    recommendations = []
    
    for question in questionnaire.questions:
        answer_key = f'answer_{question.id}'
        comment_key = f'comment_{question.id}'
        
        if answer_key not in request.form:
            flash('Please answer all questions.', 'error')
            return redirect(url_for('third_party_questionnaire', token=token))
        
        answer = request.form[answer_key]
        comment = request.form.get(comment_key, '').strip()
        
        # Validate answer
        if answer not in ['yes', 'no', 'partial', 'na']:
            flash('Invalid answer provided.', 'error')
            return redirect(url_for('third_party_questionnaire', token=token))
        
        # Store response
        response = QuestionnaireResponse(
            questionnaire_id=questionnaire.id,
            question_id=question.id,
            answer=answer,
            comments=comment
        )
        db.session.add(response)
        
        # Count answers
        if answer == 'yes':
            total_yes += 1
        elif answer == 'no':
            total_no += 1
            recommendations.append({
                'question': question.question_text,
                'category': question.category,
                'weight': question.weight,
                'recommendation': get_recommendation(question.category, question.question_text)
            })
        elif answer == 'partial':
            total_partial += 1
            recommendations.append({
                'question': question.question_text,
                'category': question.category,
                'weight': question.weight,
                'recommendation': get_recommendation(question.category, question.question_text)
            })
        else:  # na
            total_na += 1
    
    # Calculate risk score
    risk_score = calculate_risk_score(questionnaire.questions, total_yes, total_no, total_partial, total_na)
    risk_rating = get_risk_rating(risk_score)
    
    # Update questionnaire status
    questionnaire.status = 'Completed'
    questionnaire.completed_date = datetime.utcnow()
    
    # Create risk assessment
    assessment = RiskAssessment(
        user_id=questionnaire.user_id,
        questionnaire_id=questionnaire.id,
        third_party_name=questionnaire.third_party_name,
        questionnaire_name=questionnaire.name,
        risk_score=risk_score,
        risk_rating=risk_rating,
        total_questions=len(questionnaire.questions),
        yes_answers=total_yes,
        no_answers=total_no,
        partial_answers=total_partial,
        na_answers=total_na,
        recommendations=json.dumps(recommendations)
    )
    
    db.session.add(assessment)
    db.session.commit()
    
    # Log the completion
    log_security_event(questionnaire.user_id, 'questionnaire_completed', 'questionnaire', str(questionnaire.id),
                      details=f"Questionnaire completed by {questionnaire.third_party_name}")
    
    # Send email notification (simulated)
    flash('Questionnaire completed successfully! The requestor has been notified.', 'success')
    return redirect(url_for('third_party_questionnaire', token=token))

# Risk Assessment Routes

@app.route('/assessments')
@login_required
def assessments():
    """View risk assessments"""
    user_assessments = RiskAssessment.query.filter_by(user_id=current_user.id).order_by(RiskAssessment.assessment_date.desc()).all()
    return render_template('assessments.html', assessments=user_assessments)

@app.route('/assessment/<int:assessment_id>')
@login_required
def assessment_detail(assessment_id):
    """View detailed risk assessment"""
    assessment = RiskAssessment.query.filter_by(id=assessment_id, user_id=current_user.id).first()
    if not assessment:
        abort(404)
    
    questionnaire = Questionnaire.query.get(assessment.questionnaire_id)
    responses = QuestionnaireResponse.query.filter_by(questionnaire_id=assessment.questionnaire_id).all()
    
    return render_template('assessment_detail.html', 
                         assessment=assessment, 
                         questionnaire=questionnaire,
                         responses=responses)

# Helper Functions

def calculate_risk_score(questions, yes_answers, no_answers, partial_answers, na_answers):
    """Calculate risk score based on responses"""
    total_weight = 0
    risk_points = 0
    
    for question in questions:
        weight = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}[question.weight]
        total_weight += weight
    
    # Find responses for this assessment
    questionnaire_responses = QuestionnaireResponse.query.filter_by(questionnaire_id=question.id).all()
    
    for response in questionnaire_responses:
        weight = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}[response.question.weight]
        
        if response.answer == 'no':
            risk_points += weight * 10
        elif response.answer == 'partial':
            risk_points += weight * 5
    
    if total_weight == 0:
        return 0
    
    return min(100, round((risk_points / (total_weight * 10)) * 100))

def get_risk_rating(score):
    """Get risk rating based on score"""
    if score >= 75:
        return 'Critical'
    elif score >= 50:
        return 'High'
    elif score >= 25:
        return 'Medium'
    else:
        return 'Low'

def get_recommendation(category, question):
    """Get security recommendation based on category and question"""
    recommendations = {
        'Access Control': 'Implement stronger access controls including MFA, role-based access control (RBAC), and regular access reviews.',
        'Data Protection': 'Enhance data protection measures with encryption at rest and in transit, and implement data classification.',
        'Governance': 'Develop and document comprehensive security policies and procedures with regular updates.',
        'Compliance': 'Establish regular audit processes and maintain compliance documentation for relevant standards.',
        'Incident Management': 'Create and test incident response procedures regularly with clear escalation paths.',
        'Network Security': 'Implement network segmentation, firewalls, and intrusion detection/prevention systems.',
        'Training': 'Conduct regular security awareness training and phishing simulations for all employees.',
        'Business Continuity': 'Develop and test disaster recovery and business continuity plans regularly.'
    }
    
    return recommendations.get(category, 'Review and improve security practices in this area.')

# Error handlers

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', code=404, message='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', code=500, message='Internal server error'), 500

# CLI commands

@app.cli.command()
def init_db_command():
    """Initialize the database."""
    init_db()
    print('Database initialized.')

# Initialize database before first request
@app.before_first_request
def create_tables():
    init_db()

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)