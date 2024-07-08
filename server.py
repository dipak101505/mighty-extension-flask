import os
import json
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
from firebase_admin import auth, exceptions
from supabase import create_client, Client
from firebase_admin._auth_utils import EmailAlreadyExistsError
from datetime import datetime # Import datetime module



from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
import hashlib
import requests

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

cred = credentials.Certificate("permission.json")
default_app = firebase_admin.initialize_app(cred)

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

db = firestore.client()

# Salt rounds for password hashing
salt_rounds = 10

# Flask app setup
app = Flask(__name__)
CORS(app)

# Hashing function for URLs
def hash_url(url):
    return hashlib.sha256(url.encode('utf-8')).hexdigest()

def insert_data(data):
    try:
        response = supabase.table('scraped_data').insert(data).execute()
        print(f"Inserted {len(response.data)} rows of data!")
    except Exception as e:
        print(f"Error inserting data: {e}")


# Scrape data from a URL
def scrape_data(url, user_id):
    token = os.environ.get('TOKEN')
    base_url = os.environ.get('BASEURL')

    print(url)
    encoded_url = requests.utils.quote(url)
    print(encoded_url)
    encoded_token = requests.utils.quote(token)
    # encoded_url="https%3A%2F%2Fglebekitchen.com%2Fpizza-margherita-neapolitan-style%2F"
    full_url = f"{base_url}?token={encoded_token}&url={url}"
    print(full_url)
    try:
        response = requests.get(full_url, headers={'accept': 'application/json'})
        response.raise_for_status()  # Raise an exception for bad status codes

        data = response.json()
        
        title = data["objects"][0]['title']
        text = data["objects"][0]['text']
        
        if user_id:
            d = [{'title': title, 'body': text,'email' : user_id , 'url': url}]
            insert_data(d)
            

    except requests.exceptions.RequestException as e:
        print(f"Error fetching || scraping || saving data: {e}")

# Fetch search results
async def fetch_data(input, user_id):
    try:
        modified_input = input.replace(' ', ' & ')
        print(modified_input)
        query = f"""
                SELECT
                    id,
                    title,
                    ts_headline(body, q, 'StartSel=<b>, StopSel=</b>') AS matched_sentence,
                    ts_rank(tsvector_col, q) AS rank
                FROM
                    scraped_data,
                    to_tsquery('english', '{modified_input}') AS q
                WHERE
                    tsvector_col @@ q
                    AND 
                    scraped_data.email = '{user_id}'
                ORDER BY
                    rank DESC
            """

        # print((query))
        # Execute the query using supabase.rpc
        response = supabase.rpc('my_sql', {"query": query}).execute()

        print(len(response.data))

        # Handle the response
        if response.data and len(response.data) > 0:
            data = response.data
            
        else:
            print(f"Error fetching data: {response}")

        return response.data

    except Exception as e:
        print(f"Error fetching data: {e}")
        raise

# Get user details
def get_user_details(user_id):
    try:
        user_record = auth.get_user(user_id)
        print(f"Successfully fetched user data: {user_record}")
        return user_record
    except Exception as e:
        print(f"Error fetching user data: {e}")
        raise

# Hash password
async def hash_password(password):
    salt = bcrypt.gensalt(salt_rounds)
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

# Login route
@app.route('/login', methods=['POST'])
async def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    print(f"Email: {email}, Password: {password}")
    print(default_app.name)   

    print(firebase_admin)
    try:
        user_record = auth.get_user_by_email(email)

        user_doc = db.collection('users').document(user_record.uid).get()

        if not user_doc.exists:
            return jsonify({'message': 'User data not found in Firestore.'}), 400

        user = user_doc.to_dict()

        # Verify password
        password_match = bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8'))
        if not password_match:
            return jsonify({'message': 'Invalid password.'}), 401

        # Generate a custom token for the user
        token = user_record.uid
        return jsonify({
            'message': 'User logged in successfully',
            'userId': user_record.uid,
            'token': token,
            'email': user_record.email
        }), 200

    except exceptions.AuthError as e:
        if e.code == 'auth/user-not-found':
            return jsonify({'message': 'No user found with this email.'}), 400
        else:
            return jsonify({'message': 'An unknown error occurred.'}), 500

# Signup route
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    try:
        # Synchronously hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(salt_rounds)).decode('utf-8')

        user_response = auth.create_user(
            email=email,
            password=password,
            email_verified=False,
            disabled=False
        )
        print('Successfully created new user: {0}'.format(user_response.uid))

        db.collection('users').document(user_response.uid).set({
            'email': email,
            'password': hashed_password
        })

        return jsonify({
            'message': 'User registered successfully',
            'userId': user_response.uid,
            'email': email
        }), 201

    except EmailAlreadyExistsError:
        return jsonify({'message': 'The email address is already in use by another account.'}), 400
    except ValueError as e:
        if 'password' in str(e):
            return jsonify({'message': 'The password is too weak.'}), 400
        else:
            return jsonify({'message': 'The email address is not valid.'}), 400
    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {e}")
        return jsonify({'message': 'An unknown error occurred.'}), 500
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'message': 'An unknown error occurred.'}), 500

# Save URL and scrape data
@app.route('/save', methods=['POST'])
def save_url():
    token = request.headers.get('Authorization')
    data = request.get_json()
    if 'url' not in data:
        return jsonify({"error": "URL not provided"}), 400

    url = data['url']
    print(f"Received URL: {url}")
    try:
        if not token:
            return jsonify({'message': 'Token is missing in the request.'}), 401

        user_details = get_user_details(token.split(' ')[1])
        print(f"User Details: {user_details.email}")

        if user_details.email:
           scrape_data(url, user_details.email)

        return jsonify({'message': 'URL and token verified and saved successfully'}), 200

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'message': str(e)}), 401

# Get search list
@app.route('/search/<input>', methods=['GET'])
async def search(input):
    token = request.headers.get('Authorization')

    try:
        if not token:
            return jsonify({'message': 'Token is missing in the request.'}), 401

        user_details = get_user_details(token.split(' ')[1])
        print(f"User Details: {user_details.email}")

        data = await fetch_data(input, user_details.email) if user_details.email else []
        print(data)
        return jsonify({'message': 'Fetched List successfully', 'data': data}), 200

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'message': str(e)}), 401

if __name__ == '__main__':
    app.run(debug=True)
