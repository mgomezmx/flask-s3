from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import boto3
from botocore.exceptions import ClientError

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///media_backup.db'
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change in production
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

class S3Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    access_key = db.Column(db.String(80), nullable=False)
    secret_key = db.Column(db.String(120), nullable=False)
    bucket_name = db.Column(db.String(80), nullable=False)

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(username=data['username'], password_hash=hashed_pw)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token)
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/link-s3', methods=['POST'])
@jwt_required()
def link_s3():
    current_user = get_jwt_identity()
    data = request.get_json()
    s3_cred = S3Credential(
        user_id=current_user,
        access_key=data['access_key'],
        secret_key=data['secret_key'],
        bucket_name=data['bucket_name']
    )
    db.session.add(s3_cred)
    db.session.commit()
    return jsonify({"message": "S3 credentials linked"}), 201

@app.route('/upload', methods=['POST'])
@jwt_required()
def upload():
    current_user = get_jwt_identity()
    s3_cred = S3Credential.query.filter_by(user_id=current_user).first()
    
    if not s3_cred:
        return jsonify({"error": "No S3 credentials linked"}), 400
    
    file = request.files['file']
    s3 = boto3.client(
        's3',
        aws_access_key_id=s3_cred.access_key,
        aws_secret_access_key=s3_cred.secret_key
    )
    
    try:
        s3.upload_file(
            file.filename,
            s3_cred.bucket_name,
            file.filename
        )
        return jsonify({"message": "File uploaded"}), 200
    except ClientError as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
