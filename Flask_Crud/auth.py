import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
import boto3
from botocore.exceptions import ClientError
import logging
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

logger = logging.getLogger(__name__)

# Configure DynamoDB
dynamodb = boto3.resource(
    'dynamodb',
    endpoint_url='http://localhost:8000',
)
users_table = dynamodb.Table('Users')

SECRET_KEY = "71a0665e-750f-4fea-80f8-8912f8da72a8" 

def create_token(user_id: str) -> str:
    payload = {
        'exp': datetime.utcnow() + timedelta(days=1),
        'iat': datetime.utcnow(),
        'sub': user_id
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token:
            logger.warning("No token provided in request")
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user_id = payload['sub']
        except jwt.ExpiredSignatureError:
            logger.warning("Expired token used")
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            logger.warning("Invalid token used")
            return jsonify({'message': 'Invalid token'}), 401
        
        return f(current_user_id, *args, **kwargs)
    
    return decorated

def create_user(user_data: dict) -> dict:
    try:
        user_data['password'] = generate_password_hash(user_data['password'])
        user_data['user_id'] = str(uuid.uuid4())
        user_data['created_at'] = datetime.utcnow().isoformat()
        
        users_table.put_item(Item=user_data)
        return user_data
    except ClientError as e:
        logger.error(f"Error creating user: {str(e)}")
        raise

def authenticate_user(email: str, password: str) -> dict:
    try:
        response = users_table.scan(
            FilterExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        
        if not response['Items']:
            return None
            
        user = response['Items'][0]
        if check_password_hash(user['password'], password):
            return user
        return None
    except ClientError as e:
        logger.error(f"Error authenticating user: {str(e)}")
        raise 