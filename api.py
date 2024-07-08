from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import datetime
import jwt
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'fjdjvhkjcdvhjkdjhgdhudgdubjinhvbjkhbjncbdhnhbnjv'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:RolnESUCsEEMvlPrnEVnbsdYfapcKxzh@monorail.proxy.rlwy.net:17844/railway'
db = SQLAlchemy(app)

class User(db.Model):
    userId = db.Column(db.String(50), primary_key=True, unique=True)
    firstName = db.Column(db.String(50), nullable=False)
    lastName = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20))

class Organisation(db.Model):
    orgId = db.Column(db.String(50), primary_key=True, unique=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    users = db.relationship('User', secondary='organisation_user', backref=db.backref('organisations', lazy='dynamic'))

organisation_user = db.Table('organisation_user',
    db.Column('user_id', db.String(50), db.ForeignKey('user.userId')),
    db.Column('org_id', db.String(50), db.ForeignKey('organisation.orgId'))
)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(userId=data['userId']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    required_fields = ['firstName', 'lastName', 'email', 'password']
    missing_fields = [field for field in required_fields if field not in data]

    if missing_fields:
        errors = [{"field": field, "message": f"{field} is required"} for field in missing_fields]
        return jsonify({"errors": errors}), 422

    if User.query.filter_by(email=data['email']).first():
        return jsonify({
            "errors": [
                {"field": "email", "message": "Email already exists"}
            ]
        }), 422

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(
        userId=str(uuid.uuid4()),
        firstName=data['firstName'],
        lastName=data['lastName'],
        email=data['email'],
        password=hashed_password,
        phone=data.get('phone')
    )
    db.session.add(new_user)
    db.session.commit()

    org_name = f"{data['firstName']}'s Organisation"
    new_org = Organisation(orgId=str(uuid.uuid4()), name=org_name, description='')
    new_org.users.append(new_user)
    db.session.add(new_org)
    db.session.commit()

    token = jwt.encode({'userId': new_user.userId, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

    return jsonify({
        "status": "success",
        "message": "Registration successful",
        "data": {
            "accessToken": token,
            "user": {
                "userId": new_user.userId,
                "firstName": new_user.firstName,
                "lastName": new_user.lastName,
                "email": new_user.email,
                "phone": new_user.phone,
            }
        }
    }), 201

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()

    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({"status": "Bad request", "message": "Authentication failed", "statusCode": 401}), 401

    token = jwt.encode({'userId': user.userId, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

    return jsonify({
        "status": "success",
        "message": "Login successful",
        "data": {
            "accessToken": token,
            "user": {
                "userId": user.userId,
                "firstName": user.firstName,
                "lastName": user.lastName,
                "email": user.email,
                "phone": user.phone,
            }
        }
    }), 200

@app.route('/api/users/<id>', methods=['GET'])
@token_required
def get_user(current_user, id):
    if current_user.userId != id:
        return jsonify({"message": "Cannot perform that function!"})

    user = User.query.filter_by(userId=id).first()

    if not user:
        return jsonify({"message": "User not found!"})

    return jsonify({
        "status": "success",
        "message": "User found",
        "data": {
            "userId": user.userId,
            "firstName": user.firstName,
            "lastName": user.lastName,
            "email": user.email,
            "phone": user.phone
        }
    }), 200

@app.route('/api/organisations', methods=['GET'])
@token_required
def get_organisations(current_user):
    organisations = current_user.organisations

    return jsonify({
        "status": "success",
        "message": "Organisations found",
        "data": {
            "organisations": [
                {
                    "orgId": org.orgId,
                    "name": org.name,
                    "description": org.description,
                } for org in organisations
            ]
        }
    }), 200

@app.route('/api/organisations/<orgId>', methods=['GET'])
@token_required
def get_organisation(current_user, orgId):
    organisation = Organisation.query.filter_by(orgId=orgId).first()

    if not organisation or current_user not in organisation.users:
        return jsonify({"message": "Organisation not found or access denied"}), 404

    return jsonify({
        "status": "success",
        "message": "Organisation found",
        "data": {
            "orgId": organisation.orgId,
            "name": organisation.name,
            "description": organisation.description,
        }
    }), 200

@app.route('/api/organisations', methods=['POST'])
@token_required
def create_organisation(current_user):
    data = request.get_json()
    if 'name' not in data:
        return jsonify({"message": "Organisation name is required"}), 400

    new_org = Organisation(orgId=str(uuid.uuid4()), name=data['name'], description=data.get('description', ''))
    new_org.users.append(current_user)
    db.session.add(new_org)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Organisation created successfully",
        "data": {
            "orgId": new_org.orgId,
            "name": new_org.name,
            "description": new_org.description
        }
    }), 201

@app.route('/api/organisations/<orgId>/users', methods=['POST'])
@token_required
def add_user_to_organisation(current_user, orgId):
    data = request.get_json()
    user = User.query.filter_by(userId=data['userId']).first()
    organisation = Organisation.query.filter_by(orgId=orgId).first()

    if not user or not organisation or current_user not in organisation.users:
        return jsonify({"message": "User or Organisation not found or access denied"}), 404

    organisation.users.append(user)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "User added to organisation successfully"
    }), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
