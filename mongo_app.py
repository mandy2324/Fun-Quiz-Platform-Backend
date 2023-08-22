from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from pymongo import MongoClient
import re
import bcrypt
from bson import ObjectId

 
app = Flask(__name__)

app.secret_key = 'xyzsdfg'

# Initialize MongoDB client
client = MongoClient("mongodb+srv://admin:password101@interactivequizdb.x3sik2a.mongodb.net/")
db = client.get_database("bookstore_db")
users_collection = db.user


def is_user_logged_in():
    return 'user_id' in session

@app.route('/index')
def index():
    first_name = None
    last_name = None
    user_logged_in = is_user_logged_in()
    if user_logged_in:
        # Fetch the username based on user_id
        user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
        if user:
            first_name = user.get('first_name')
            last_name = user.get('last_name')
    return render_template('index.html', user_logged_in=user_logged_in, first_name=first_name, last_name=last_name)
 
@app.route('/login', methods=['GET', 'POST'])
def login():
    registration_success = request.args.get('registration_success')
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users_collection.find_one({'username': username})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['user_id'] = str(user['_id'])
            return redirect(url_for('index'))
        else:
            return render_template('login.html', message='Invalid credentials')
    return render_template('login.html', registration_success=registration_success)

 
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))
 
@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ''
    first_name = None
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not all([first_name, last_name, username, email, password]):
            message = 'Please fill out all the fields!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            message = 'Invalid email address!'
        elif users_collection.find_one({'email': email}):
            message = 'Account already exists!'
        else:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            user_data = {
                'first_name': first_name,
                'last_name': last_name,
                'username': username,
                'email': email,
                'password': hashed_password  # Store the hashed password as bytes
            }
            users_collection.insert_one(user_data)
            message = 'You have successfully registered!'
            
            return redirect(url_for('login', registration_success=True))

    return render_template('register.html', message=message, first_name=first_name)

   
if __name__ == "__main__":
    app.run(host='localhost', port=5001, debug=True)