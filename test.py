from flask import Flask, request, jsonify
import sqlite3
import random
import os
import base64
from email.mime.text import MIMEText
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Initialize the Flask application
app = Flask(__name__)

# Define the scope for Gmail API (to send emails)
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

# Initialize the database
def init_db():
    '''
    Initialize the SQLite database.

    This method creates a database file named 'user_database.db' if it does not already exist.
    It also creates two tables:
    
    1. `users` table: Stores user information including `id` (primary key), `username` (unique), and `password`.
    2. `otp` table: Stores OTP (One-Time Password) information, including `id` (primary key), `username`, and `otp`.

    If the tables already exist, this method does nothing.

    Returns:
        None
    '''
    conn = sqlite3.connect('user_database.db')  # Connect to the SQLite database (or create it if it doesn't exist)
    cursor = conn.cursor()  # Create a cursor to execute SQL statements
    
    # Create the 'users' table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    # Create the 'otp' table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS otp (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        otp TEXT NOT NULL
    )
    ''')
    conn.commit()  # Save the changes
    conn.close()  # Close the database connection

init_db()  # Initialize the database

# To get or refresh credentials for Gmail API
def get_credentials():
    '''
    Retrieve or refresh Gmail API credentials.

    This function checks if a valid token file exists. If it does, it loads the credentials.
    If the token is expired or not found, the function uses OAuth 2.0 to refresh or generate new credentials
    and saves them to a file named 'token.json' for future use.

    Returns:
        creds (Credentials): The authenticated credentials for Gmail API.
    '''

    # Initialize credentials as None
    creds = None

    # Check if token file exists
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    # If no credentials or credentials are invalid
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:    # If expired, refresh credentials
            creds.refresh(Request())
        else:   # Otherwise, perform the OAuth flow
            flow = InstalledAppFlow.from_client_secrets_file('client_secret.json', SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials to token.json
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return creds

# To send an OTP email
def send_otp_email(receiver_email, otp):
    '''
    Send an OTP email to the specified recipient.

    This function uses Gmail API to send an email containing the OTP code to the recipient's email address.

    Args:
        receiver_email (str): The email address of the recipient.
        otp (str): The OTP code to be sent.

    Returns:
        None
    '''

    # Get Gmail API credentials
    creds = get_credentials()
    # Create the Gmail API service
    service = build('gmail', 'v1', credentials=creds)

    sender_email = 'yanh8587@gmail.com'  # Send OTP from this email address
    subject = 'Your OTP Code'   # Subject of the email
    body = f'Your OTP code is: {otp}'   # Body of the email

    message = MIMEText(body)    # Create the email content
    message['to'] = receiver_email  # Set recipient email
    message['from'] = sender_email  # Set sender email
    message['subject'] = subject    # Set subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode() # Encode email as base64

    try:
        # Send the email via Gmail API
        service.users().messages().send(userId='me', body={'raw': raw}).execute()
        print('Email sent successfully.')
    except Exception as e:
        print(f'Failed to send email: {e}')
    
# To register a new user
@app.route('/register', methods=['POST'])
def register_user():
    '''
    Register a new user in the database.

    This endpoint accepts a JSON payload with a username and password,
    and registers the user in the SQLite database.

    Input:
        JSON:
        {
            "username": "user@example.com",
            "password": "securepassword"
        }

    Returns:
        JSON response indicating success or error.
    '''
     
    data = request.json  # Get JSON data from the request
    username = data.get('username')  # Extract the username
    password = data.get('password')  # Extract the password

    # Check if username or password is missing
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400


    try:
        conn = sqlite3.connect('user_database.db')  # Connect to the SQLite database
        cursor = conn.cursor()  # Create a cursor for executing SQL commands
        # Insert the new user into the 'users' table
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()  # Commit the changes
        conn.close()  # Close the database connection
        return jsonify({"message": "User registered successfully"}), 201  # Return success message
    except sqlite3.IntegrityError:  # Handle duplicate username error
        return jsonify({"error": "Username already exists"}), 409   # Return a 409 Conflict response indicating the username already exists.

# To verify username and password
@app.route('/login', methods=['POST'])
def login_user():
    '''
    Authenticate a user and generate an OTP.

    This endpoint verifies the provided username and password against the database.
    If valid, it generates a one-time password (OTP) and sends it to the user's email.

    Input:
        JSON:
        {
            "username": "user@example.com",
            "password": "securepassword"
        }

    Returns:
        JSON response indicating success or error.
    '''

    data = request.json  # Get JSON data from the request
    username = data.get('username')  # Extract the username
    password = data.get('password')  # Extract the password

    if not username or not password:    # Check if username or password is missing
        return jsonify({"error": "Username and password are required"}), 400    # Bad Request

    conn = sqlite3.connect('user_database.db')  # Connect to the SQLite database
    cursor = conn.cursor()  # Create a cursor for executing SQL commands
    # Check if the user exists with the given username and password
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    user = cursor.fetchone()  # Fetch the user record
    conn.close()  # Close the database connection

    if user:  # If user exists
        otp = str(random.randint(100000, 999999))  # Generate a random 6-digit OTP
        conn = sqlite3.connect('user_database.db')  # Connect to the SQLite database
        cursor = conn.cursor()  # Create a cursor for executing SQL commands
        # Insert the OTP into the 'otp' table
        cursor.execute('INSERT INTO otp (username, otp) VALUES (?, ?)', (username, otp))
        conn.commit()  # Commit the changes
        conn.close()  # Close the database connection

        send_otp_email(username, otp)  # Send the OTP email

        return jsonify({"message": "Username and password verified. OTP sent to your email."}), 200
    else:  # If user does not exist
        return jsonify({"error": "Invalid username or password."}), 401     # Unauthorized 

# To verify OTP and log in
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    '''
    Verify a user's OTP for login.

    This endpoint checks if the provided OTP matches the one in the database.
    If valid, the OTP is removed from the database, and the user is logged in.

    Input:
        JSON:
        {
            "username": "user@example.com",
            "otp": "123456"
        }

    Returns:
        JSON response indicating success or error.
    '''

    data = request.json  # Get JSON data from the request
    username = data.get('username')  # Extract the username
    otp = data.get('otp')  # Extract the OTP

    if not username or not otp:  # Check if username or OTP is missing
        return jsonify({"error": "Username and OTP are required"}), 400     # Bad Request

    conn = sqlite3.connect('user_database.db')  # Connect to the SQLite database
    cursor = conn.cursor()  # Create a cursor for executing SQL commands
    # Check if the OTP matches the username in the 'otp' table
    cursor.execute('SELECT * FROM otp WHERE username = ? AND otp = ?', (username, otp))
    otp_entry = cursor.fetchone()  # Fetch the OTP record

    if otp_entry:  # If OTP is valid
        cursor.execute('DELETE FROM otp WHERE username = ?', (username,))  # Delete the OTP entry
        conn.commit()  # Commit the changes
        conn.close()  # Close the database connection
        return jsonify({"message": "Login successful"}), 200
    else:  # If OTP is invalid
        conn.close()  # Close the database connection
        return jsonify({"error": "Invalid OTP"}), 401   # Unauthorized 

# Start the Flask application
if __name__ == '__main__':
    app.run(debug=True)
