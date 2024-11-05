from flask import Flask, request, jsonify
import boto3
from botocore.exceptions import ClientError

app = Flask(__name__)

# Configure DynamoDB
dynamodb = boto3.resource(
    'dynamodb',
    endpoint_url='http://localhost:8000',
)

# Reference to our table
table = dynamodb.Table('Books')

@app.route('/')
def hello():
    return jsonify({"message": "Welcome to Flask DynamoDB CRUD API!"})

# CREATE - Add a new book
@app.route('/books', methods=['POST'])
def create_book():
    try:
        print("Creating a new book...")
        book_data = request.get_json()
        print(book_data)
        # Ensure required fields are present
        if not all(key in book_data for key in ('bookId', 'title', 'author')):
            return jsonify({'error': 'Missing required fields'}), 400
        
        response = table.put_item(
            Item={
                'bookId': book_data['bookId'],
                'title': book_data['title'],
                'author': book_data['author'],
                'price': book_data.get('price', 0),
                'category': book_data.get('category', 'Uncategorized')
            }
        )
        print(response)
        return jsonify({'message': 'Book created successfully'}), 201
    
    except ClientError as e:
        return jsonify({'error': str(e)}), 500

# READ - Get a book by ID
@app.route('/books/<book_id>', methods=['GET'])
def get_book(book_id):
    try:
        response = table.get_item(
            Key={
                'bookId': book_id
            }
        )
        
        if 'Item' in response:
            return jsonify(response['Item'])
        return jsonify({'error': 'Book not found'}), 404
    
    except ClientError as e:
        return jsonify({'error': str(e)}), 500

# UPDATE - Update a book
@app.route('/books/<book_id>', methods=['PUT'])
def update_book(book_id):
    try:
        book_data = request.get_json()
        
        # Build update expression and attribute values
        update_expr = "SET "
        expr_values = {}
        
        for key, value in book_data.items():
            if key != 'bookId':  # Skip the primary key
                update_expr += f"#{key} = :{key}, "
                expr_values[f":{key}"] = value
        
        # Remove trailing comma and space
        update_expr = update_expr[:-2]
        
        # Build expression attribute names
        expr_names = {f"#{k}": k for k in book_data.keys() if k != 'bookId'}
        
        response = table.update_item(
            Key={
                'bookId': book_id
            },
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_values,
            ExpressionAttributeNames=expr_names,
            ReturnValues="UPDATED_NEW"
        )
        
        return jsonify(response['Attributes'])
    
    except ClientError as e:
        return jsonify({'error': str(e)}), 500

# DELETE - Delete a book
@app.route('/books/<book_id>', methods=['DELETE'])
def delete_book(book_id):
    try:
        response = table.delete_item(
            Key={
                'bookId': book_id
            }
        )
        return jsonify({'message': 'Book deleted successfully'})
    
    except ClientError as e:
        return jsonify({'error': str(e)}), 500

# LIST - Get all books
@app.route('/books', methods=['GET'])
def list_books():
    try:
        response = table.scan()
        return jsonify(response['Items'])
    
    except ClientError as e:
        return jsonify({'error': str(e)}), 500

# Get all books
@app.route('/all_books', methods=['GET'])
def get_all_books():
    try:
        response = table.scan()
        books = response.get('Items', [])
        
        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            books.extend(response.get('Items', []))
            
        return jsonify({
            'status': 'success',
            'count': len(books),
            'books': books
        }), 200
    
    except ClientError as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True)