from flask import Flask, request, jsonify
import boto3
from botocore.exceptions import ClientError
from datetime import datetime
import uuid
import logging
from auth import token_required, create_user, authenticate_user, create_token
from models import TodoCreate, TodoUpdate, UserRegister, UserLogin

# Configure logging to write to a file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()  # This will still print logs to the console
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configure DynamoDB
dynamodb = boto3.resource(
    'dynamodb',
    endpoint_url='http://localhost:8000',
)

# Reference to our tables
todos_table = dynamodb.Table('Todos')

@app.route('/register', methods=['POST'])
def register():
    try:
        user_data = UserRegister(**request.get_json())
        user = create_user(user_data.dict())
        logger.info(f"New user registered: {user['email']}")
        return jsonify({'message': 'User created successfully'}), 201
    except ValueError as e:
        logger.error(f"Validation error during registration: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error during registration: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = UserLogin(**request.get_json())
        user = authenticate_user(data.email, data.password)
        if user:
            token = create_token(user['user_id'])
            logger.info(f"User logged in: {user['email']}")
            return jsonify({'token': token})
        logger.warning(f"Failed login attempt for email: {data.email}")
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/todos', methods=['POST'])
@token_required
def create_todo(current_user_id):
    try:
        logger.info("Creating new todo")
        todo_data = TodoCreate(**request.get_json())
        
        todo_item = {
            'todo_id': str(uuid.uuid4()),
            'user_id': current_user_id,
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat(),
            'task': todo_data.task,
            'status': todo_data.status.value
        }
        
        todos_table.put_item(Item=todo_item)
        logger.info(f"Todo created successfully: {todo_item['todo_id']}")
        return jsonify({'message': 'Todo created successfully', 'todo': todo_item}), 201
    
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except ClientError as e:
        logger.error(f"DynamoDB error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/todos/<todo_id>', methods=['GET'])
@token_required
def get_todo(current_user_id, todo_id):
    try:
        response = todos_table.get_item(
            Key={'todo_id': todo_id}
        )
        
        if 'Item' in response:
            todo = response['Item']
            if todo['user_id'] != current_user_id:
                logger.warning(f"Unauthorized access attempt to todo {todo_id}")
                return jsonify({'error': 'Unauthorized'}), 403
            return jsonify(todo)
        
        logger.info(f"Todo not found: {todo_id}")
        return jsonify({'error': 'Todo not found'}), 404
    
    except ClientError as e:
        logger.error(f"Error retrieving todo: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/todos/<todo_id>', methods=['PUT'])
@token_required
def update_todo(current_user_id, todo_id):
    try:
        # First check if the todo exists and belongs to the user
        existing_todo = todos_table.get_item(Key={'todo_id': todo_id})
        if 'Item' not in existing_todo:
            return jsonify({'error': 'Todo not found'}), 404
        if existing_todo['Item']['user_id'] != current_user_id:
            return jsonify({'error': 'Unauthorized'}), 403

        todo_data = TodoUpdate(**request.get_json())
        
        # Build update expression
        update_expr = "SET updated_at = :updated_at"
        expr_values = {':updated_at': datetime.utcnow().isoformat()}
        
        update_data = todo_data.dict(exclude_unset=True)
        for key, value in update_data.items():
            if value is not None:
                update_expr += f", #{key} = :{key}"
                expr_values[f":{key}"] = value.value if key == 'status' else value
        
        # Build expression attribute names
        expr_names = {f"#{k}": k for k in update_data.keys()}
        
        response = todos_table.update_item(
            Key={'todo_id': todo_id},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_values,
            ExpressionAttributeNames=expr_names,
            ReturnValues="ALL_NEW"
        )
        
        logger.info(f"Todo updated successfully: {todo_id}")
        return jsonify({'message': 'Todo updated successfully', 'todo': response['Attributes']})
    
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except ClientError as e:
        logger.error(f"DynamoDB error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/todos/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user_id, todo_id):
    try:
        # First check if the todo exists and belongs to the user
        existing_todo = todos_table.get_item(Key={'todo_id': todo_id})
        if 'Item' not in existing_todo:
            return jsonify({'error': 'Todo not found'}), 404
        if existing_todo['Item']['user_id'] != current_user_id:
            return jsonify({'error': 'Unauthorized'}), 403

        todos_table.delete_item(
            Key={'todo_id': todo_id}
        )
        logger.info(f"Todo deleted successfully: {todo_id}")
        return jsonify({'message': 'Todo deleted successfully'})
    
    except ClientError as e:
        logger.error(f"Error deleting todo: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/todos', methods=['GET'])
@token_required
def list_todos(current_user_id):
    try:
        response = todos_table.scan(
            FilterExpression='user_id = :user_id',
            ExpressionAttributeValues={':user_id': current_user_id}
        )
        todos = response['Items']
        
        while 'LastEvaluatedKey' in response:
            response = todos_table.scan(
                ExclusiveStartKey=response['LastEvaluatedKey'],
                FilterExpression='user_id = :user_id',
                ExpressionAttributeValues={':user_id': current_user_id}
            )
            todos.extend(response['Items'])
        
        logger.info(f"Retrieved {len(todos)} todos for user {current_user_id}")
        return jsonify({
            'status': 'success',
            'count': len(todos),
            'todos': todos
        }), 200
    
    except ClientError as e:
        logger.error(f"Error listing todos: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)