import boto3
import os

def create_tables():
    dynamodb = boto3.resource('dynamodb', endpoint_url=os.getenv('DATABASE_ENDPOINT'))
    
    # Create Todos table
    todos_table = dynamodb.create_table(
        TableName='Todos',
        KeySchema=[
            {
                'AttributeName': 'todo_id',
                'KeyType': 'HASH'
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'todo_id',
                'AttributeType': 'S'
            }
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    
    # Create Users table
    users_table = dynamodb.create_table(
        TableName='Users',
        KeySchema=[
            {
                'AttributeName': 'user_id',
                'KeyType': 'HASH'
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'user_id',
                'AttributeType': 'S'
            }
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    
    print("Tables created successfully!")

if __name__ == "__main__":
    create_tables() 