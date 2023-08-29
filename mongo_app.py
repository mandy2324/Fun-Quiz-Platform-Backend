from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from pymongo import MongoClient
import re
import bcrypt
from bson import ObjectId
from flask_cors import CORS

 
app = Flask(__name__)
CORS(app) # i do not know if this chaged anything but feel free to take out
app.secret_key = 'xyzsdfg'

# Initialize MongoDB client
client = MongoClient("mongodb+srv://admin:password101@interactivequizdb.x3sik2a.mongodb.net/")
db = client.get_database("users")
users_collection = db.users
questions_collection = db.questions

def is_user_logged_in():
    return 'user_id' in session

#Check if user session is true
@app.route('/check-login', methods=['GET'])
def check_login():
    if 'user_id' in session:
        user_id = session['user_id']
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if user:
            user_info = {
                "logged_in": True,
                "user": {
                    "first_name": user.get('first_name'),
                    "last_name": user.get('last_name'),
                    # Add other user details
                }
            }
            return jsonify(user_info), 200
    return jsonify({"logged_in": False}), 200

#User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data:
        return jsonify({"message": "Request data missing."}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required fields."}), 400

    user = users_collection.find_one({'username': username})
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        session['user_id'] = str(user['_id'])
        return jsonify({"message": "Login successful."}), 200
    else:
        return jsonify({"message": "Invalid credentials."}), 401  # Unauthorized status code

# User Logout 
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return jsonify({"message": "Logout successful."}), 200




#creating restful friendly endpoints to interact with postman/react
# User registration
@app.route('/register', methods=['POST'])
def register():
    #data will be in Json format
    data = request.get_json()
    #if not in appropriate format or missing, send a message
    if not data:
        return jsonify({"message": "Request data missing."}), 400

    #grabbing the json attributes for user
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not all([first_name, last_name, username, email, password]):
        return jsonify({"message": "Please fill out all the fields!"}), 400
    elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
        return jsonify({"message": "Invalid email address!"}), 400
    elif users_collection.find_one({'email': email}):
        return jsonify({"message": "Account already exists!"}), 409  # Conflict status code
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
        return jsonify({"message": "You have successfully registered!"}), 201  # Created status code

#Questions Endpoint
#Create Question
@app.route('/questions', methods=['POST'])
def create_question():
    if not is_user_logged_in():
        return jsonify({"message": "You must be logged in to add a question."}), 401

    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not user:
        return jsonify({"message": "You must be logged in to add a question."}), 401

    data = request.get_json()
    if not data:
        return jsonify({"message": "Request data missing."}), 400

    question = data.get('question')
    answer = data.get('answer')
    category = data.get('category')
    difficulty = data.get('difficulty')

    try:
        value = int(difficulty)
        if value < 0 or value > 5:
            return jsonify({"message": "Difficulty value must be between 0 and 5."}), 400
    except ValueError:
        return jsonify({"message": "Invalid difficulty value."}), 400

    if not question or not answer:
        return jsonify({"message": "Please insert at least a question and its answer."}), 400

    if questions_collection.find_one({'question': question}):
        return jsonify({"message": "Question already exists."}), 409

    question_data = {
        'question': question,
        'answer': answer,
        'category': category,
        'difficulty': difficulty
    }
    questions_collection.insert_one(question_data)
    return jsonify({"message": "Question added successfully."}), 201

#Delete Question
@app.route('/questions/delete', methods=['POST'])
def delete_question():
    if not is_user_logged_in():
        return jsonify({"message": "You must be logged in to delete a question."}), 401
    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})

    if not user:
        return jsonify({"message": "You must be logged in to delete a question."}), 401
    data = request.get_json()
    
    if not data:
        return jsonify({"message": "Request data missing."}), 400
    question = data.get('question')
    if not question:
        return jsonify({"message": "Please provide the question to delete."}), 400


    deleted_question = questions_collection.find_one_and_delete({'question': question})
    if not deleted_question:
        return jsonify({"message": "Question not found."}), 404

    return jsonify({"message": "Question deleted successfully."}), 200

@app.route('/quiz/list', methods=['GET'])
def get_question_list():
    if not is_user_logged_in():
        return jsonify({"message": "You must be logged in to add a question."}), 401

    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    
    questions = list(questions_collection.find({}))  # Fetch all questions from the collection
    question_list = []

    for question in questions:
        question_item = {
            'question': question['question'],
            'answer': question['answer'],
            'category': question['category'],
            'difficulty': question['difficulty']
        }
        question_list.append(question_item)

    return jsonify(question_list), 200


#Quiz Endpoints
#Get Question : Custom query to get a number of questions 
#Get Question by difficulty : Query questions that have a difficulty specified
#Get Question by Category: Query Questions from a specific category
=======
#Update Question

#Quiz Endpoints
#Get Question : Custom query to get a number of questions 
#Get Question by difficulty : Query questions that have a difficulty specified
#Get Question by Category: Query Questions from a specific category

@app.route('/get-questions-by-category', methods=['GET'])
def get_questions_by_catagory():
    category = request.args.get('category')

    query = {}
    if category:
        query['category'] = category
    else:
        return jsonify({"message": "Invalid category value."}), 400
    questions = questions_collection.find(query)

    question_list = []
    for question in questions:
        question_list.append({
            "question": question.get('question'),
            "answer": question.get('answer'),
            "category": question.get('category'),
            "difficulty": question.get('difficulty')
        })

    return jsonify(question_list), 200
#Using a POST
@app.route('/get-questions-by-category', methods=['POST'])
def get_questions_by_catagory_2():

    data = request.get_json()
    if not data:
        return jsonify({"message": "Request data missing."}), 400

    category = data.get('category')

    query = {}
    if category:
        query['category'] = category
    else:
        return jsonify({"message": "Invalid category value."}), 400
    questions = questions_collection.find(query)

    question_list = []
    for question in questions:
        question_list.append({
            "question": question.get('question'),
            "answer": question.get('answer'),
            "category": question.get('category'),
            "difficulty": question.get('difficulty')
        })

    return jsonify(question_list), 200

@app.route('/get-questions-by-difficulty', methods=['POST'])
def get_questions_by_difficulty():
    data = request.get_json()
    if not data:
        return jsonify({"message": "Request data missing."}), 400

    difficulty = data.get('difficulty')
    query = {}
    if difficulty:
        query['difficulty'] = difficulty
    else:
        return jsonify({"message": "Invalid difficulty value."}), 400

    questions = questions_collection.find(query)

    question_list = []
    for question in questions:
        question_list.append({
            "question": question.get('question'),
            "answer": question.get('answer'),
            "category": question.get('category'),
            "difficulty": question.get('difficulty')
        })

    return jsonify(question_list), 200

@app.route('/get-questions-both', methods=['POST'])
def get_questions():
    data = request.get_json()
    category = data.get('category')
    difficulty = data.get('difficulty')

    query = {}
    if category:
        query['category'] = category
    if difficulty:
        query['difficulty'] = difficulty

    questions = questions_collection.find(query)

    question_list = []
    for question in questions:
        question_list.append({
            "question_text": question.get('question'),
            "answer": question.get('answer'),
            "category": question.get('category'),
            "difficulty": question.get('difficulty')
            # Add other question details
        })

    return jsonify(question_list), 200


if __name__ == "__main__":
    app.run(host='localhost', port=5001, debug=True)