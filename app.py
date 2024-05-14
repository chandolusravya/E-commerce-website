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
import stripe
from flask_caching import Cache
import redis

# Define the database model
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='mysql+pymysql://root:password@localhost/ecommerce'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
db= SQLAlchemy(app)

# Define Stripe keys
app.config['STRIPE_PUBLIC_KEY'] = "pk_test_51PEF3nAHMNnu39Cn5uhEfrWm1RBfrh9YSvXO0Nud2En7TVQ9j1vHSLAfBtLtSoDyw695Lsqkk8HnUKS8kpvtni6500niC1iyrL"
app.config['STRIPE_SECRET_KEY'] = "stripe_secret_key" # add the stripe secret key

# Set stripe key
stripe.api_key = app.config['STRIPE_SECRET_KEY']

app.secret_key = "secret_key" #replace with the google client secret key
app.config['UPLOAD_FOLDER'] = 'images/'
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "711397492344-gkkhoaga48j5a613o0olq4t90kgndf27.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

login_manager = LoginManager(app)
login_manager.init_app(app)

#caching configuration
# Define the configuration for Redis caching
app.config['CACHE_TYPE'] = 'redis'
app.config['CACHE_REDIS_HOST'] = 'localhost'
app.config['CACHE_REDIS_PORT'] = 6379
# Initialize the Flask-Caching extension
cache = Cache(app)

# Initialize Redis client 
redis_client = redis.Redis(host='localhost', port=6379, db=0)

class User(db.Model,UserMixin):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    address = db.Column(db.String(150))
    city = db.Column(db.String(150))
    state = db.Column(db.String(150))
    pincode = db.Column(db.String(150))
    country = db.Column(db.String(150))
    home = db.Column(db.String(150))
    
    orders = db.relationship('Orders', backref='user', lazy=True)

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
    price = db.Column(db.Integer)
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

class Orders(db.Model):
    __tablename__ = 'Orders'
    id = db.Column(db.Integer, primary_key=True)
    # Define other columns for order details
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'), nullable=False)


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
   
    
# Route to handle home page
@app.route('/',methods=['GET'])
def home():
    loggedIn, firstName, noOfItems = get_loggedin_details()
    # user_is_logged_in = current_user.is_authenticated
    message = "Welcome to Our E-Commerce Website"
    all_products = Products.query.all()
    # cache.set('cached_data', all_products, timeout=60)
    return render_template('mainpage.html', user_is_logged_in=loggedIn, message=message, all_products=all_products, firstName=firstName)


# Route to handle login
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

# Route to handle signup
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


# Route to handle oauth callback
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

# Route to handle oauthlogin
@app.route("/oauthlogin")
def oauthlogin():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

# Route to handle logout
@app.route('/logout')
def logout():
    # logout_user()  # Flask-Login function to log out the user
    session.pop('email', None)
    # session.clear()  # Clear any session variables
    flash('You have been logged out.', 'success')  # Flash a success message
    return redirect(url_for('home'))  # Redirect the user to the home page after logout


# Route to handle addItem for admin
@app.route('/addItem',methods=['GET','POST'])
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

# Route to handle checkout
@app.route('/checkout')
def checkout():
    if 'email' not in session:
        return redirect(url_for('login'))  # Redirect to login if user is not logged in

    user = User.query.filter_by(email=session['email']).first()
    if not user:
        return redirect(url_for('login'))  # Redirect to login if user is not found

    # Fetch products from the cart using SQLAlchemy
    products = db.session.query(Products.price) \
                         .join(Kart, Products.id == Kart.product_id) \
                         .filter(Kart.user_id == user.id) \
                         .all()

    # Calculate total price
    total_price = sum(product.price for product in products)

    # Create a Stripe checkout session
    stripe_session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'usd',
                'unit_amount': int(total_price * 100),  # Convert total price to cents
                'product_data': {
                    'name': 'Your Product',  # Replace with your product name
                },
            },
            'quantity': 1,
        }],
        mode='payment',
        success_url=url_for('addItem', _external=True),
        cancel_url=url_for('cart', _external=True),
    )

    # Redirect the user to the Stripe checkout page with the session URL
    return redirect(stripe_session.url, code=303)

# Route to handle cart webpage
@app.route("/cart", methods =['GET'])
def cart():
    if 'email' not in session:
        return redirect(url_for('login'))

    user_is_logged_in, firstName, noOfItems = get_loggedin_details()
    email = session['email']

    # Retrieve user from the database
    user = User.query.filter_by(email=email).first()

    # Ensure the user exists
    if not user:
        return render_template("login.html", message="User not found")

    # Get the user's ID
    user_id = user.id

    # Fetch products from the cart using SQLAlchemy
    products = db.session.query(Products.id, Products.name, Products.price, Products.image_url) \
                         .join(Kart, Products.id == Kart.product_id) \
                         .filter(Kart.user_id == user_id) \
                         .all()

    # Calculate total price
    totalPrice = sum(product.price for product in products)

    return render_template("cart.html", products=products, totalPrice=totalPrice, user_is_logged_in=user_is_logged_in, firstName=firstName, noOfItems=noOfItems)

# Route to handle add to cart 
@app.route("/addToCart")
def addToCart():
    if 'email' not in session:
        return redirect(url_for('login'))
    else:
        productId = int(request.args.get('productId'))
        user = User.query.filter_by(email=session['email']).first()

        if not user:
            return redirect(url_for('login'))

        userId = user.id
        
        # Check if the product already exists in the user's cart
        existing_kart_entry = Kart.query.filter_by(user_id=userId, product_id=productId).first()

        if existing_kart_entry:
            # Product already exists in the cart, provide feedback to the user
            flash('Product already exists in the cart', 'warning')
            return redirect(url_for('cart'))

        # If the product does not exist in the cart, add it
        new_kart_entry = Kart(user_id=userId, product_id=productId)
        db.session.add(new_kart_entry)
        # db.session.add(session['email'])
        db.session.commit()
        
        # Provide feedback to the user that the product was added successfully
        flash('Product added successfully to the cart', 'success')
        
        # Redirect to the cart route after adding the product to the cart
        return redirect(url_for('cart'))


# Route to handle remove from cart
@app.route("/removefromCart")
def removefromCart():
    if 'email' not in session:
        # Flash message for users not logged in
        flash("Please log in to remove items from the cart.", "message")
        return redirect(url_for('login'))
    else:
        productId = int(request.args.get('productId'))
        user = User.query.filter_by(email=session['email']).first()

        if not user:
            # Flash message for user not found
            flash("User not found.", "error")
            return redirect(url_for('login'))

        userId = user.id
        
        # Check if the product exists in the user's cart
        existing_kart_entry = Kart.query.filter_by(user_id=userId, product_id=productId).first()

        if not existing_kart_entry:
            # Flash message for product not found in the cart
            flash("Product not found in the cart.", "error")
            return redirect(url_for('cart'))

        # If the product exists in the cart, remove it
        db.session.delete(existing_kart_entry)
        db.session.commit()
        
        # Flash message for successful removal
        flash("Product removed successfully from the cart.", "success")

        # Redirect to the cart route after removing the product from the cart
        return redirect(url_for('cart'))


# Route to handle product description
@app.route("/productDescription/<int:productid>",methods=['GET'])
@cache.cached(60*60*24*7)
def productDescription(productid):
    # Get the productId from the request
    details = Products.query.get(productid)
    print("Caching all products...")

    # Render the product description template with the product details
    return render_template('productDescription.html', product=details, productId=productid)

@app.route("/category/<int:c_id>",methods=['GET'])
@cache.cached(60*60*24*7)
def get_category(c_id):
    details = Products.query.filter_by(category_id=c_id).all()  # Assuming 3 is the category_id for books
    print(details) 
        
    return render_template("displayCategory.html", books=details)


from flask import render_template

@app.route('/orders')
def orders():
    if 'email' not in session:
        return redirect(url_for('login'))  # Redirect to login if user is not logged in

    user = User.query.filter_by(email=session['email']).first()
    if user:
        return render_template('no_orders.html', user_is_logged_in=False)

    orders = user.orders.all()
    user_is_logged_in, _, _ = get_loggedin_details()

    return render_template('orders.html', user_is_logged_in=user_is_logged_in, orders=orders)



# Route to handle update profile
@app.route('/updateProfile', methods=['POST','GET'])
def updateProfile():
        if 'email' not in session:
            return redirect(url_for('login'))
       
        user = User.query.filter_by(email=session['email']).first()
        if not user:
            return redirect(url_for('login'))  # Redirect to login if user is not found

        if request.method == "POST":
            
            # Get the form data
            first_name = request.form.get('firstName')
            address1 = request.form.get('address1')
            zipcode = request.form.get('zipcode')
            city = request.form.get('city')
            state = request.form.get('state')
            country = request.form.get('country')
            phone_number = request.form.get('phone')

            # Update the user's profile
            user.first_name = first_name
            user.address = address1
            user.pincode = zipcode
            user.city = city
            user.state = state
            user.country = country
            user.home = phone_number

            # Commit changes to the database
            db.session.commit()
            
            flash('Profile updated successfully!', category='success')

        user_is_logged_in, firstName, _ = get_loggedin_details()
        
        # Redirect to the profile page or any other appropriate page
        return render_template("editProfile.html", profileData=user, user_is_logged_in=user_is_logged_in, firstName=firstName)


if __name__=='__main__':
    app.run(port= 5000,debug=True)

