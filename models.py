import os
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """User model following Secure-by-Design principles"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    company_name = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Security fields
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    
    # Relationships
    questionnaires = db.relationship('Questionnaire', backref='user', lazy=True, cascade='all, delete-orphan')
    scan_reports = db.relationship('ScanReport', backref='user', lazy=True, cascade='all, delete-orphan')
    risk_assessments = db.relationship('RiskAssessment', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Secure password hashing"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Secure password verification"""
        return check_password_hash(self.password_hash, password)
    
    def is_account_locked(self):
        """Check if account is temporarily locked"""
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False
    
    def increment_failed_attempts(self):
        """Increment failed login attempts with lockout"""
        self.failed_login_attempts += 1
        # Lock account after 5 failed attempts for 15 minutes
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.utcnow().replace(minute=datetime.utcnow().minute + 15)
    
    def reset_failed_attempts(self):
        """Reset failed login attempts on successful login"""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.utcnow()

class QuestionnaireTemplate(db.Model):
    """Pre-built questionnaire templates"""
    __tablename__ = 'questionnaire_templates'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    template_type = db.Column(db.String(50), nullable=False)  # standard, cloud, gdpr
    
    questions = db.relationship('Question', backref='template', lazy=True, cascade='all, delete-orphan')

class Question(db.Model):
    """Individual security questions"""
    __tablename__ = 'questions'
    
    id = db.Column(db.Integer, primary_key=True)
    template_id = db.Column(db.Integer, db.ForeignKey('questionnaire_templates.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    weight = db.Column(db.String(20), nullable=False)  # critical, high, medium, low
    
    # For custom questions from user-generated questionnaires
    is_custom = db.Column(db.Boolean, default=False)

class Questionnaire(db.Model):
    """User-created questionnaires for third parties"""
    __tablename__ = 'questionnaires'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    third_party_name = db.Column(db.String(255), nullable=False)
    third_party_email = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default='Sent')  # Sent, In Progress, Completed
    share_token = db.Column(db.String(255), unique=True, nullable=False)
    sent_date = db.Column(db.DateTime, default=datetime.utcnow)
    completed_date = db.Column(db.DateTime)
    
    # Relationships
    questions = db.relationship('QuestionnaireQuestion', backref='questionnaire', lazy=True, cascade='all, delete-orphan')
    responses = db.relationship('QuestionnaireResponse', backref='questionnaire', lazy=True, cascade='all, delete-orphan')

class QuestionnaireQuestion(db.Model):
    """Questions assigned to specific questionnaires"""
    __tablename__ = 'questionnaire_questions'
    
    id = db.Column(db.Integer, primary_key=True)
    questionnaire_id = db.Column(db.Integer, db.ForeignKey('questionnaires.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    weight = db.Column(db.String(20), nullable=False)

class QuestionnaireResponse(db.Model):
    """Third-party responses to questionnaire questions"""
    __tablename__ = 'questionnaire_responses'
    
    id = db.Column(db.Integer, primary_key=True)
    questionnaire_id = db.Column(db.Integer, db.ForeignKey('questionnaires.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('questionnaire_questions.id'), nullable=False)
    answer = db.Column(db.String(50), nullable=False)  # yes, no, partial, na
    comments = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    question = db.relationship('QuestionnaireQuestion')

class ScanReport(db.Model):
    """Passive security scan reports"""
    __tablename__ = 'scan_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target = db.Column(db.String(255), nullable=False)  # Domain or IP
    scan_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), default='completed')  # pending, completed, failed
    progress = db.Column(db.Integer, default=0)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    completion_date = db.Column(db.DateTime)
    
    # Scan results (stored as JSON)
    findings = db.Column(db.Text)  # JSON string
    
    def set_findings(self, findings_dict):
        """Store findings as JSON"""
        import json
        self.findings = json.dumps(findings_dict)
    
    def get_findings(self):
        """Retrieve findings as dictionary"""
        import json
        return json.loads(self.findings) if self.findings else {}

class RiskAssessment(db.Model):
    """Risk assessments based on questionnaire responses"""
    __tablename__ = 'risk_assessments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    questionnaire_id = db.Column(db.Integer, db.ForeignKey('questionnaires.id'), nullable=False)
    third_party_name = db.Column(db.String(255), nullable=False)
    questionnaire_name = db.Column(db.String(255), nullable=False)
    
    # Risk calculation results
    risk_score = db.Column(db.Integer, nullable=False)  # 0-100
    risk_rating = db.Column(db.String(20), nullable=False)  # Low, Medium, High, Critical
    assessment_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Risk assessment data
    total_questions = db.Column(db.Integer)
    yes_answers = db.Column(db.Integer, default=0)
    no_answers = db.Column(db.Integer, default=0)
    partial_answers = db.Column(db.Integer, default=0)
    na_answers = db.Column(db.Integer, default=0)
    
    # Report generation
    report_generated = db.Column(db.Boolean, default=False)
    report_path = db.Column(db.String(500))
    
    # Recommendations
    recommendations = db.Column(db.Text)  # JSON string

class LogEntry(db.Model):
    """Centralized logging for security and audit purposes"""
    __tablename__ = 'log_entries'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    resource = db.Column(db.String(100))
    resource_id = db.Column(db.String(100))
    ip_address = db.Column(db.String(45))  # IPv6 compatible
    user_agent = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=True)
    details = db.Column(db.Text)
    
    def log_action(cls, user_id, action, resource=None, resource_id=None, 
                   ip_address=None, user_agent=None, success=True, details=None):
        """Class method to create log entries"""
        log_entry = cls(
            user_id=user_id,
            action=action,
            resource=resource,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            details=details
        )
        db.session.add(log_entry)
        db.session.commit()
        return log_entry