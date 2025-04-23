from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import uuid
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///expense_tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Replace with secure, environment-variable-stored key
db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app)  # Enable CORS for React frontend (http://localhost:8000)

# Models
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class Category(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    name = db.Column(db.String(50), nullable=False)

class Transaction(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.Date, nullable=False)
    category_id = db.Column(db.String(36), db.ForeignKey('category.id'), nullable=False)
    type = db.Column(db.String(20), nullable=False)  # income/expense
    description = db.Column(db.Text, nullable=True)

class PasswordResetToken(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

# Input Validation
def validate_user_data(data):
    errors = []
    if not data.get('username') or len(data['username']) < 3:
        errors.append('Username must be at least 3 characters long')
    if not data.get('email') or '@' not in data['email']:
        errors.append('Valid email is required')
    if not data.get('password') or len(data['password']) < 8:
        errors.append('Password must be at least 8 characters long')
    return errors

# Simulate Email Sending (for development)
def send_reset_email(email, token):
    print(f"Simulated email to {email}: Password reset link: http://localhost:8000/reset-password?token={token}")
    # In production, use a real email service (e.g., Flask-Mail, SMTP)
    return True

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    errors = validate_user_data(data)
    if errors:
        return jsonify({'message': 'Validation errors', 'errors': errors}), 400
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 400
    
    password_hash = generate_password_hash(password)
    user = User(username=username, email=email, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    access_token = create_access_token(identity=user.id)
    return jsonify({'access_token': access_token}), 200

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Email not found'}), 404
    
    # Generate reset token
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=1)  # Token valid for 1 hour
    reset_token = PasswordResetToken(user_id=user.id, token=token, expires_at=expires_at)
    db.session.add(reset_token)
    db.session.commit()
    
    # Send reset email (simulated for development)
    if send_reset_email(email, token):
        return jsonify({'message': 'Password reset link sent to your email'}), 200
    else:
        return jsonify({'message': 'Failed to send reset link'}), 500

@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('password')
    
    if len(new_password) < 8:
        return jsonify({'message': 'Password must be at least 8 characters long'}), 400
    
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    if not reset_token or reset_token.expires_at < datetime.utcnow():
        return jsonify({'message': 'Invalid or expired reset token'}), 400
    
    user = User.query.get(reset_token.user_id)
    user.password_hash = generate_password_hash(new_password)
    
    # Invalidate the token
    db.session.delete(reset_token)
    db.session.commit()
    
    return jsonify({'message': 'Password reset successfully'}), 200

@app.route('/transactions', methods=['POST'])
@jwt_required()
def add_transaction():
    data = request.get_json()
    user_id = get_jwt_identity()
    
    try:
        transaction = Transaction(
            user_id=user_id,
            amount=float(data['amount']),
            date=datetime.strptime(data['date'], '%Y-%m-%d').date(),
            category_id=data['category_id'],
            type=data['type'],
            description=data.get('description')
        )
        db.session.add(transaction)
        db.session.commit()
        return jsonify({'message': 'Transaction added'}), 201
    except (ValueError, KeyError) as e:
        return jsonify({'message': 'Invalid transaction data', 'error': str(e)}), 400

@app.route('/transactions', methods=['GET'])
@jwt_required()
def get_transactions():
    user_id = get_jwt_identity()
    transactions = Transaction.query.filter_by(user_id=user_id).all()
    return jsonify([{
        'id': t.id,
        'amount': t.amount,
        'date': t.date.isoformat(),
        'category': Category.query.get(t.category_id).name if t.category_id else 'Uncategorized',
        'type': t.type,
        'description': t.description
    } for t in transactions]), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(debug=True)