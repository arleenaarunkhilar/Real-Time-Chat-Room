from flask import Flask
from flask_session import Session
from flask_socketio import SocketIO
import eventlet
from eventlet import wsgi

app = Flask(__name__)
app.secret_key = 'ak260704'
app.config["SECRET"] = "ak260704"
app.config["SESSION_TYPE"] = "filesystem"
# Initialize Flask-Session
Session(app)

# Initialize Flask-SocketIO
socketIO = SocketIO(app, manage_session=False)

# Import routes and SocketIO event handlers

if __name__ == "__main__":
    # Run the Flask-SocketIO server

    wsgi.server(eventlet.listen(("127.0.0.1", 8000)), app)
