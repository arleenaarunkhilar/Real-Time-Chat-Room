from flask import Flask, request, session, redirect, url_for, render_template, flash
import psycopg2, pymongo
import psycopg2.extras
import re
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import join_room, leave_room, emit
from app import app, socketIO
from datetime import datetime
import eventlet
from eventlet import wsgi
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
import models.authModel


DB_HOST = "localhost"
DB_NAME = "user_db"
DB_USER = "postgres"
DB_PASS = "password"

conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)

client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client['chat_db']
chat_history_collection = db['chat_history']

@app.route('/')
def home():
    # Check if user is loggedin
    if 'loggedin' in session:

        # User is loggedin show them the home page
        return render_template('home.html', username=session['username'])
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.route('/login/', methods=['GET', 'POST'])
def login():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        print(password)

        # Check if account exists using MySQL
        cursor.execute('SELECT * FROM logins WHERE username = %s', (username,))
        # Fetch one record and return result
        account = cursor.fetchone()

        if account:
            password_rs = account['password']
            print(password_rs)
            # If account exists in users table in out database
            if check_password_hash(password_rs, password):
                # Create session data, we can access this data in other routes
                session['loggedin'] = True
                session['username'] = account['username']
                # Redirect to home page
                return redirect(url_for('home'))
            else:
                # Account doesnt exist or username/password incorrect
                flash('Incorrect username/password')
        else:
            # Account doesnt exist or username/password incorrect
            flash('Incorrect username/password')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        _hashed_password = generate_password_hash(password)

        #Check if account exists using MySQL
        cursor.execute('SELECT * FROM logins WHERE username = %s', (username,))
        account = cursor.fetchone()
        print(account)
        # If account exists show error and validation checks
        if account:
            flash('Account already exists!')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!')
        elif not re.match(r'[A-Za-z0-9]+', username):
            flash('Username must contain only characters and numbers!')
        elif not username or not password or not email:
            flash('Please fill out the form!')
        else:
            # Account doesnt exists and the form data is valid, now insert new account into users table
            cursor.execute("INSERT INTO logins ( username, password, email) VALUES (%s,%s,%s)", ( username, _hashed_password, email))
            conn.commit()
            flash('You have successfully registered!')
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        flash('Please fill out the form!')
    # Show registration form with message (if any)
    return render_template('register.html')


@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('username', None)
   # Redirect to login page
   return redirect(url_for('login'))

@app.route('/profile')
def profile():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Check if user is loggedin
    if 'loggedin' in session:
        cursor.execute('SELECT * FROM logins WHERE username = %s', [session['username']])
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('profile.html', account=account)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.route("/index", methods=['GET','POST'])
def index():
    return render_template("index.html")

@app.route("/join", methods=["GET", "POST"])
def join():
    # check for a post method
    if (request.method == "POST"):
        print("post method")
        # get form data
        room_name: str = request.form["roomName"]

        # store user data in session
        session["room_name"] = room_name


        # return template(chatRoom template)
        return render_template("chatroom.html", session=session)
    else:
        # handle logged in user page refresh
        if (session.get("username") is not None):
            return render_template("chatroom.html", session=session)
        else:
            # user in not logged in/ does not have a session
            # need to join a room
            return redirect(url_for("index"))

def save_message(room, username, message):
    chat_history_collection.insert_one({
        "room_name": room,
        "username": username,
        "message": message,
        "timestamp": datetime.now()
    })

def get_chat_history(room):
    messages = chat_history_collection.find({"room_name": room}).sort("timestamp", pymongo.ASCENDING)
    return [{"username": msg["username"], "message": msg["message"]} for msg in messages]

@socketIO.on("join", namespace="/join")
def handle_join(message):
    roomName = session.get("room_name")
    username = session.get("username")
    join_room(roomName)
    chat_history = get_chat_history(roomName)
    for msg in chat_history:
        emit("message", {"msg": f"{msg['username']}: {msg['message']}"}, room=request.sid)
    welcome_message = f"{username} has joined the chat room!!"
    save_message(roomName, "System", welcome_message)
    emit("status", {"msg": welcome_message}, room=roomName)

@socketIO.on("text", namespace="/join")
def handle_text(message):
    roomName = session.get("room_name")
    username = session.get("username")
    msg = f"{username}: {message['msg']}"
    save_message(roomName, username, message['msg'])
    emit("message", {"msg": msg}, room=roomName)

@socketIO.on("left", namespace="/join")
def handle_left(message):
    roomName = session.get("room_name")
    username = session.get("username")
    leave_room(roomName)
    session.clear()
    leave_message = f"{username} has left the chat room"
    save_message(roomName, "System", leave_message)
    emit("status", {"msg": leave_message}, room=roomName)


if __name__ == "__main__":
    socketIO.run(app, debug=True, port=8000)
