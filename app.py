import flask
from flask import render_template, redirect, url_for, request, flash
from flask_login import login_required, logout_user, LoginManager, login_user
from werkzeug.security import generate_password_hash, check_password_hash

from database.database import db, init_database
import database.models as models
from config.config import Config

app = flask.Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return models.User.query.filter_by(email=user).first()


with app.test_request_context():
    init_database()


@app.route('/')
@app.route('/home')
def home():
    return render_template("index.html")


@app.route('/profile')
@login_required
def profile():
    return render_template("profile.html")


@app.route('/signup', methods=['GET'])
def signup_form():
    return render_template("signup.html")


@app.route('/signup', methods=['POST'])
def signup():
    username = flask.request.form.get("username")
    email = flask.request.form.get("email")
    password = flask.request.form.get("password")

    user = models.User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database
    if user: # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email address already exists')
        return redirect(url_for('signup'))

    user = models.User.query.filter_by(username=username).first() # if this returns a user, then the username already exists in database
    if user: # if a user is found, we want to redirect back to signup page so user can try again
        flash('Username address already exists')
        return redirect(url_for('signup'))

    if username and email:
        user = models.User(username=username,
                           email=email,
                           password=generate_password_hash(password, method='sha256'))
        db.session.add(user)
        db.session.commit()
    else:
        return "Please fill the form"
    return profile()


@app.route('/login', methods=['GET', 'POST'])
def login():
    user = None
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        user = models.User.query.filter_by(username=username).first()

        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the hashed password in the database
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return render_template("login.html") # if the user doesn't exist or password is wrong, reload the page

    else:
        return render_template("login.html")
    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return render_template("profile.html")


@app.route("/logout", methods=["GET"])
@login_required
def logout():
    """Logout the current user."""
    logout_user()
    return render_template("index.html")


@app.route('/users')
@login_required
def show_users():
    users_list = models.User.query.all()
    return render_template("users.html", users_list=users_list)
