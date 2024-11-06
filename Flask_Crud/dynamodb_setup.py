import boto3
import os

def create_tables():
    dynamodb = boto3.resource('dynamodb', endpoint_url=os.getenv('DATABASE_ENDPOINT'))
    
    # List of tables to create with their schemas
    tables_to_create = {
        'Todos': {
            'KeySchema': [{'AttributeName': 'todo_id', 'KeyType': 'HASH'}],
            'AttributeDefinitions': [{'AttributeName': 'todo_id', 'AttributeType': 'S'}]
        },
        'Users': {
            'KeySchema': [{'AttributeName': 'user_id', 'KeyType': 'HASH'}],
            'AttributeDefinitions': [{'AttributeName': 'user_id', 'AttributeType': 'S'}]
        }
    }
    
    existing_tables = [table.name for table in dynamodb.tables.all()]
    
    for table_name, schema in tables_to_create.items():
        if table_name not in existing_tables:
            try:
                table = dynamodb.create_table(
                    TableName=table_name,
                    KeySchema=schema['KeySchema'],
                    AttributeDefinitions=schema['AttributeDefinitions'],
                    ProvisionedThroughput={
                        'ReadCapacityUnits': 5,
                        'WriteCapacityUnits': 5
                    }
                )
                print(f"Table {table_name} created successfully!")
            except Exception as e:
                print(f"Error creating table {table_name}: {str(e)}")
        else:
            print(f"Table {table_name} already exists!")
