# Flask DynamoDB CRUD API

## Setup
1. Create a virtual environment: `python -m venv venv`
2. Activate the virtual environment: `source venv/bin/activate` for windows use `venv\Scripts\activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Run `python dynamodb_setup.py` to create the `Books` table in DynamoDB.
5. Run `python app.py` to start the Flask server.