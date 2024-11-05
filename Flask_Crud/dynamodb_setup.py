import boto3
from botocore.exceptions import ClientError

# Configure DynamoDB client
dynamodb = boto3.client(
    'dynamodb',
    endpoint_url='http://localhost:8000', 
)

def table_exists(table_name):
    try:
        dynamodb.describe_table(TableName=table_name)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return False
        raise e

# Create the table
def create_books_table():
    try:
        # Check if table already exists
        if table_exists('Books'):
            print("Table 'Books' already exists!")
            return None
            
        # Create table if it doesn't exist
        response = dynamodb.create_table(
            TableName='Books',
            KeySchema=[
                {
                    'AttributeName': 'bookId',
                    'KeyType': 'HASH'  # Partition key
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'bookId',
                    'AttributeType': 'S'  # String type
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
        print("Table created successfully!")
        return response
        
    except Exception as e:
        print(f"Error creating table: {str(e)}")
        return None

if __name__ == '__main__':
    create_books_table() 