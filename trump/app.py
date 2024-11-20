import os
import sqlite3
import secrets # Changes: Added to replace hardcoded secret key
import re # Changes: Added to secure search route
import html # Changes: Added to secure search route
from flask import Flask, render_template, request, Response, redirect, url_for, flash, session, send_from_directory, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from datetime import timedelta # Changes: Added to enforce session expiry

# Changed: Added secure key generator
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # ** Changed: Replaced hardcoded key with dynamically generated key

# Changes: Added secure session cookie configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,  # Ensures cookies are only sent over HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Prevent access via JavaScript
)

# Changes: Added session timeout 
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Configure the SQLite database
db_path = os.path.join(os.path.dirname(__file__), 'trump.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db = SQLAlchemy(app)

# Example Model (Table)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# Function to run the SQL script if database doesn't exist
def initialize_database():
    if not os.path.exists('trump.db'):
        with sqlite3.connect('trump.db') as conn:
            cursor = conn.cursor()
            with open('trump.sql', 'r') as sql_file:
                sql_script = sql_file.read()
            cursor.executescript(sql_script)
            print("Database initialized with script.")

# Existing routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/quotes')
def quotes():
    return render_template('quotes.html')

@app.route('/sitemap')
def sitemap():
    return render_template('sitemap.html')
    
@app.route('/admin_panel', methods=['GET'])
def admin_panel():
    if 'user_id' in session and session['user_id'] == 'admin':
        return render_template('admin_panel.html')
    else:
        flash('Access restricted. Admins only.', 'error')
        return redirect(url_for('login'))

# Route to handle redirects based on the destination query parameter
@app.route('/redirect', methods=['GET'])
def redirect_handler():
    destination = request.args.get('destination')

    if destination:
        return redirect(destination)
    else:
        return "Invalid destination", 400


@app.route('/comments', methods=['GET', 'POST'])
def comments():
    if request.method == 'POST':
        username = request.form['username']
        comment_text = request.form['comment']

        # Insert comment into the database
        insert_comment_query = text("INSERT INTO comments (username, text) VALUES (:username, :text)")
        db.session.execute(insert_comment_query, {'username': username, 'text': comment_text})
        db.session.commit()
        return redirect(url_for('comments'))

    # Retrieve all comments to display
    comments_query = text("SELECT username, text FROM comments")
    comments = db.session.execute(comments_query).fetchall()
    return render_template('comments.html', comments=comments)


# Changes:
# - Path validation added to ensure that files served for download are within the 'docs' directory.
# - Directory traversal protection added to prevent access to files outside the 'docs' folder.
@app.route('/download', methods=['GET'])
def download():
    # Get the filename from the query parameter
    file_name = request.args.get('file', '')

    # Set base directory to where your docs folder is located
    base_directory = os.path.join(os.path.dirname(__file__), 'docs')

    # Construct the file path to attempt to read the file
    file_path = os.path.abspath(os.path.join(base_directory, file_name))

    # Ensure that the file path is within the base directory
    # ** Changed: Added check to prevent directory traversal and unauthorized file access.
    if not file_path.startswith(base_directory):
        return "Unauthorized access attempt!", 403

    # Try to open the file securely
    try:
        with open(file_path, 'rb') as f:
            response = Response(f.read(), content_type='application/octet-stream')
            response.headers['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response
    except FileNotFoundError:
        return "File not found", 404
    except PermissionError:
        return "Permission denied while accessing the file", 403

@app.route('/downloads', methods=['GET'])
def download_page():
    return render_template('download.html')

# Changes:
# - Added verification for current user logged in
# - Added query parameters to fetch user details securely
@app.route('/profile/<int:user_id>', methods=['GET'])
def profile(user_id):

    # Check if user is logged in 
    if 'user_id' not in session or session['user_id'] != user_id:
        return "Unauthorized access.", 403

    # Parameterized query to fetch details 
    query_user = text("SELECT * FROM users WHERE id = :id")
    user = db.session.execute(query_user, {'id': user_id}).fetchone()

    if user:
        # Parameterized query for card details
        query_cards = text("SELECT * FROM carddetail WHERE id = :id")
        cards = db.session.execute(query_cards, {'id': user_id}).fetchall()
        return render_template('profile.html', user=user, cards=cards)
    else:
        return "User not found.", 404
# Changes:
# Added alphanumeric input validation
# Sanitize query with HTML character escape
@app.route('/search', methods=['GET'])
def search():
    # Get query parameter from URL
    query = request.args.get('query', '')

    # Validate input to only allow alphanumeric characters
    if query and not re.match("^[a-zA-Z0-9 ]*$", query):  # Only letters, numbers, and spaces allowed
        return "Invalid input! Please only use alphanumeric characters."

    # Sanitize query to escape HTML characters
    sanitized_query = html.escape(query)

    # Render the template with sanitized query
    return render_template('search.html', query=sanitized_query)

@app.route('/forum')
def forum():
    return render_template('forum.html')

# Add login route
# Changes:
# - Set session as permanent for logged in user to allocate 30 minute lifetime
# - Used parameterized queries to secure login field against SQL injection
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        query = text("SELECT * FROM users WHERE username = :username AND password = :password")
        user = db.session.execute(query, {'username': username, 'password': password}).fetchone()

        if user:
            session.permanent = True # Changed: Set to permanenent for timeout
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('profile', user_id=user.id))
        else:
            error = 'Invalid Credentials. Please try again.'
            return render_template('login.html', error=error)

    return render_template('login.html')


# Logout route
# Changes:
# - Clear session data on logout
# - Disable 30 min session permanence 
@app.route('/logout')
def logout():
    session.clear()  # Changed: Added .clear instead of .pop 
    session.permanent = False # Changed: Disable session permanence
    flash('You were successfully logged out', 'success')
    return redirect(url_for('index'))
    
from flask import session


if __name__ == '__main__':
    initialize_database()  # Initialize the database on application startup if it doesn't exist
    with app.app_context():
        db.create_all()  # Create tables based on models if they don't already exist
    app.run(debug=True)
