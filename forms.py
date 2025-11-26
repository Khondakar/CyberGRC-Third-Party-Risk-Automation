from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, TextAreaField, SelectField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from models import User, Questionnaire, QuestionnaireTemplate
import re

class RegistrationForm(FlaskForm):
    """Secure registration form with validation"""
    company_name = StringField('Company Name', validators=[
        DataRequired(),
        Length(min=2, max=100, message='Company name must be between 2 and 100 characters')
    ])
    
    full_name = StringField('Full Name', validators=[
        DataRequired(),
        Length(min=2, max=100, message='Full name must be between 2 and 100 characters')
    ])
    
    email = EmailField('Email Address', validators=[
        DataRequired(),
        Email(message='Please enter a valid email address'),
        Length(max=255)
    ])
    
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, max=128, message='Password must be between 8 and 128 characters'),
        # Custom validator for password strength
    ])
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    
    submit = SubmitField('Create Account')
    
    def validate_password(self, field):
        """Custom password strength validation"""
        password = field.data
        if not re.search(r'[A-Z]', password):
            raise ValidationError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', password):
            raise ValidationError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', password):
            raise ValidationError('Password must contain at least one number')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError('Password must contain at least one special character')
    
    def validate_email(self, field):
        """Check if email already exists"""
        user = User.query.filter_by(email=field.data.lower()).first()
        if user:
            raise ValidationError('An account with this email already exists')

class LoginForm(FlaskForm):
    """Secure login form"""
    email = EmailField('Email Address', validators=[
        DataRequired(),
        Email(message='Please enter a valid email address')
    ])
    
    password = PasswordField('Password', validators=[DataRequired()])
    
    remember = BooleanField('Remember Me')
    
    submit = SubmitField('Login')

class QuestionnaireForm(FlaskForm):
    """Form for creating questionnaires"""
    name = StringField('Questionnaire Name', validators=[
        DataRequired(),
        Length(min=3, max=200, message='Name must be between 3 and 200 characters')
    ])
    
    third_party_name = StringField('Third Party Company Name', validators=[
        DataRequired(),
        Length(min=2, max=100, message='Company name must be between 2 and 100 characters')
    ])
    
    third_party_email = EmailField('Third Party Email', validators=[
        DataRequired(),
        Email(message='Please enter a valid email address')
    ])
    
    template = SelectField('Questionnaire Template', validators=[DataRequired()], coerce=int)
    
    submit = SubmitField('Create & Send Questionnaire')
    
    def __init__(self):
        super().__init__()
        # Populate template choices
        templates = QuestionnaireTemplate.query.all()
        self.template.choices = [(t.id, t.name) for t in templates]

class ScanForm(FlaskForm):
    """Form for initiating security scans"""
    target = StringField('Target Domain/IP Address', validators=[
        DataRequired(),
        Length(min=1, max=255, message='Target must be between 1 and 255 characters')
    ])
    
    scan_type = SelectField('Scan Type', validators=[DataRequired()], coerce=str)
    submit = SubmitField('Start Scan')
    
    def __init__(self):
        super().__init__()
        self.scan_type.choices = [
            ('comprehensive', 'Comprehensive Scan'),
            ('ports', 'Port Scan Only'),
            ('ssl', 'SSL/TLS Only'),
            ('dns', 'DNS Records Only')
        ]
    
    def validate_target(self, field):
        """Basic validation for domain/IP format"""
        target = field.data.strip()
        
        # Basic domain validation (simple regex)
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,})$'
        # Basic IP validation (IPv4)
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if not (re.match(domain_pattern, target) or re.match(ip_pattern, target)):
            raise ValidationError('Please enter a valid domain name or IP address')

class ThirdPartyResponseForm(FlaskForm):
    """Form for third-party questionnaire responses"""
    submit = SubmitField('Submit Questionnaire')

class CustomQuestionForm(FlaskForm):
    """Form for adding custom questions"""
    question_text = TextAreaField('Question', validators=[
        DataRequired(),
        Length(min=10, max=1000, message='Question must be between 10 and 1000 characters')
    ])
    
    category = SelectField('Category', validators=[DataRequired()], coerce=str)
    weight = SelectField('Weight', validators=[DataRequired()], coerce=str)
    submit = SubmitField('Add Question')
    
    def __init__(self):
        super().__init__()
        self.category.choices = [
            ('Governance', 'Governance'),
            ('Access Control', 'Access Control'),
            ('Data Protection', 'Data Protection'),
            ('Network Security', 'Network Security'),
            ('Compliance', 'Compliance'),
            ('Incident Management', 'Incident Management'),
            ('Training', 'Training'),
            ('Business Continuity', 'Business Continuity')
        ]
        self.weight.choices = [
            ('critical', 'Critical'),
            ('high', 'High'),
            ('medium', 'Medium'),
            ('low', 'Low')
        ]