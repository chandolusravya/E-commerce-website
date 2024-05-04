from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import requests
from werkzeug.utils import secure_filename
from sqlalchemy.sql import func
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import os
import pathlib
import bcrypt

# Define the database model
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='mysql+pymysql://root:anusha@localhost/ecommerce'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
db= SQLAlchemy(app)


#define configuration for oauth

#enable this with google secert key before running the code
# app.secret_key = "your-secrey-key"
app.config['UPLOAD_FOLDER'] = 'images/'
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

#enable this with google client id before running the code
# GOOGLE_CLIENT_ID = "your-google-client-id"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

login_manager = LoginManager(app)
login_manager.init_app(app)

class User(db.Model,UserMixin):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    @property
    def is_active(self):
        return True  # Assuming all accounts are active 
    def get_id(self):
        return str(self.id)

class Category(db.Model):
    __tablename__ = 'Category'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class Products(db.Model):
    __tablename__ = 'Products'
    id = db.Column(db.Integer, primary_key=True)
    image_url = db.Column(db.String(100))
    price = db.Column(db.String(100))
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('Category.id'))

class Kart(db.Model):
    __tablename__ = 'kart'
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'), primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('Products.id'), primary_key=True)

    # Define foreign key relationships
    user = db.relationship('User', backref='karts', primaryjoin="Kart.user_id == User.id")
    product = db.relationship('Products', backref='karts', primaryjoin="Kart.product_id == Products.id")


# Configure Flask-Login using tradition login with username and password
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_loggedin_details():
    if 'email' not in session:
        user_is_logged_in = False
        firstName = ''
        noOfItems = 0
    else:
        user = User.query.filter_by(email=session['email']).first()
        if user:
            user_is_logged_in = True
            firstName = user.first_name
            noOfItems = 1
        else:
            user_is_logged_in = False
            firstName = ''
            noOfItems = 0
            
    return (user_is_logged_in, firstName, noOfItems)
   
    

@app.route('/')
def home():
    loggedIn, firstName, noOfItems = get_loggedin_details()
    # user_is_logged_in = current_user.is_authenticated
    message = "Welcome to Our E-Commerce Website"
    all_products = Products.query.all()
    
    return render_template('mainpage.html', user_is_logged_in=loggedIn, message=message, all_products=all_products, firstName=firstName)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            flash('Logged in successfully!', category='message')
            session['email'] = email
            login_user(user, remember=True)
            return redirect(url_for('home'))
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
            hashed_password = bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt())
            new_user = User(email=email, first_name=first_name, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created successfully!', category='message')
            return redirect(url_for('login'))

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

    google_id = id_info.get("sub")
    name = id_info.get("name")
    email = id_info.get("email")
    username = email.split('@')[0]  # Extract username from email

    session["google_id"] = google_id
    session["name"] = username
    session["email"] = email

    # Check if the user already exists in the database
    user = User.query.filter_by(email=email).first()
    if not user:
        # If the user does not exist, create a new user
        new_user = User(email=email, first_name=username)
        db.session.add(new_user)
        db.session.commit()

    return redirect(url_for('home'))


@app.route("/oauthlogin")
def oauthlogin():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route('/logout')
# @login_required
def logout():
    # logout_user()  # Flask-Login function to log out the user
    session.pop('email', None)
    # session.clear()  # Clear any session variables
    # flash('You have been logged out.', 'success')  # Flash a success message
    return redirect(url_for('home'))  # Redirect the user to the home page after logout

@app.route('/addItem', methods=['POST','GET'])
def addItem():
    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        description = request.form['description']
        image_url = request.form['image']  # Assuming you're providing a URL for the image
        category_id = request.form['category']

        # Create a new Product object and add it to the database
        new_product = Products(name=name, price=price, description=description, image_url=image_url, category_id=category_id)
        db.session.add(new_product)
        db.session.commit()

        flash('Product added successfully!', category='success')
        return redirect(url_for('addItem'))  # Redirect to the add product page
    else:
         return render_template('add.html')  # Redirect to the home page if the request method is not POST

@app.route("/productDescription/<int:productid>")
def productDescription(productid):
    # Get the productId from the request
    details = Products.query.get(productid)

    # Render the product description template with the product details
    return render_template('productDescription.html', product=details)


@app.route("/category/<int:c_id>")
def get_category(c_id):
    details = Products.query.filter_by(category_id=c_id).all()  # Assuming 3 is the category_id for books
    print(details) 
        
    return render_template("displayCategory.html", books=details)


if __name__=='__main__':
    app.run(port= 5000,debug=True)
