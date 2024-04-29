from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import requests
from sqlalchemy.sql import func
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import os
import pathlib

# Define the Task model
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='mysql+pymysql://root:anusha@localhost/curd'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
# app.secret_key = 'my_secret_key'  # a secret key for flashing messages
db= SQLAlchemy(app)
login_manager = LoginManager(app)

#define configuration for oauth

app.secret_key = "add_your_key"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "711397492344-gkkhoaga48j5a613o0olq4t90kgndf27.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)


class Todo(db.Model):
    task_id = db.Column(db.Integer, primary_key=True)
    task_description=db.Column(db.String(100))
    day =db.Column(db.String(100))
    done=db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'))

class User(db.Model, UserMixin):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    notes = db.relationship('Todo') 
    @property
    def is_active(self):
        return True  # Assuming all accounts are active 

# Configure Flask-Login using tradition login with username and password
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            flash('Logged in successfully!', category='message')
            login_user(user, remember=True)
            return redirect(url_for('index'))
        else:
            flash('Incorrect email or password.', category='error')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        if password1 != password2:
            flash('Passwords do not match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters long.', category='error')
        else:
            hashed_password = generate_password_hash(password1, method='pbkdf2:sha256')
            new_user = User(email=email, first_name=first_name, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created successfully!', category='message')
            return redirect(url_for('index'))

    return render_template('signup.html')

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    # if not session["state"] == request.args["state"]:
    #     abort(500)  # State does not match!
        
    if "state" not in request.args:
        abort(400)  # Bad request, state parameter missing

    # Verify that the state parameter matches the one stored in the session
    if request.args["state"] != session.get("state"):
        abort(401)  # Unauthorized, state parameter mismatch

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect(url_for('index'))

@app.route("/oauthlogin")
def oauthlogin():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('Logged out successfully!', category='message')
    return redirect(url_for('home'))

@app.route('/todo', methods=['GET'])
# @login_required
def index():
    todo_list = Todo.query.all()
    return render_template('todo.html', todo_list=todo_list)

@app.route('/add',methods=['POST'])
def add():
    if request.method == "POST":
        name = request.form.get("task_description")
        day = request.form.get("day")
        if not(len(name) <= 0 or len(day)<=0):
            new_task=Todo(task_description=name,day=day,done=False)
            db.session.add(new_task)
            db.session.commit()   
            flash("Task added successfully", category='message')
            return redirect(url_for("created"))
        if (len(name) <= 0):
            flash("Task cannot be empty", category='warning')
        elif (len(day) <= 0):
            flash("Mention a day for the task", category='warning')
    return redirect(url_for("bad_request"))
        
@app.route('/update/<int:todo_id>', methods=['PUT','POST'])
def update(todo_id):
    todo = Todo.query.get(todo_id)
    if todo:
        todo.task_description = request.form.get('task_description')
        todo.day = request.form.get('day')
        todo.done = 'done' in request.form  # Check if 'done' checkbox is checked
        db.session.commit()
        flash("Task updated successfully",category='message')
    else:
        flash("Task not found",category='error')
        return redirect(url_for("error"))
    return redirect(url_for("index"))

@app.route('/delete/<int:todo_id>',methods=['GET','DELETE'])
def delete(todo_id):
    if request.method == 'DELETE' or request.method == 'GET':
        todo = Todo.query.get(todo_id)
        if todo:
            todo= Todo.query.get(todo_id)
            db.session.delete(todo)
            db.session.commit()
            flash("Task deleted successfully",category='message')
            return redirect(url_for("index"))
        else:
            flash("Task not found",category='error')
            return redirect(url_for("error"))
   
@app.route('/bad_request')
def bad_request():
  todo_list = Todo.query.all()
  return render_template('todo.html', todo_list=todo_list), 404

@app.route('/created')
def created():
    todo_list = Todo.query.all()
    return render_template('todo.html', todo_list=todo_list),201

@app.route('/error')
def error():
  todo_list = Todo.query.all()
  return render_template('todo.html', todo_list=todo_list), 400


if __name__=='__main__':
    app.run(debug=True)
