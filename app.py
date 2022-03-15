import flask
import sqlalchemy
from flask import render_template, redirect, url_for, request, flash
from flask_login import login_required, logout_user, LoginManager, login_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from database.database import db, init_database
import database.models as models
from config.config import Config
from datetime import datetime
from database.form import EditProfileForm, NewGroupForm

app = flask.Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)
migrate = Migrate(app, db)


@login_manager.user_loader
def load_user(user):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return models.User.query.filter_by(email=user).first()


with app.test_request_context():
    init_database()


@app.route('/')
@app.route('/home')
def home():
    #db.drop_all()
    #db.create_all()
    if current_user.is_authenticated:
        return msg_home()
    return login()


@app.route('/profile')
@login_required
def profile():
    return user(current_user.username)

@app.route('/board')
@login_required
def board():
    #db.drop_all()
    #db.create_all()
    return render_template("board.html", user=current_user )




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
    posts = []
    return msg_home()


@app.route("/logout", methods=["GET"])
@login_required
def logout():
    """Logout the current user."""
    logout_user()
    return login()


@app.route('/users')
@login_required
def show_users():
    users_list = models.User.query.all()
    return render_template("users.html", users_list=users_list)

@app.route('/user/<username>')
@login_required
def user(username):

    user_shown = models.User.query.filter_by(username=username).first_or_404()
    posts = [
        {'author': user_shown, 'body': 'Test post #1'},
        {'author': user_shown, 'body': 'Test post #2'}
    ]
    return render_template('user.html', user=user_shown, posts=posts)

@app.before_request
def before_request():

    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()



@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile',
                           form=form)


@app.route('/msg')
@login_required
def msg_home():
    discussion = models.Group.query.filter(models.Group.members.any(id=current_user.id)).first()
    if discussion is None:
        discussion = models.Group.new_group(current_user.username,current_user.id,current_user.avatar,[current_user])
    return msg_view(discussion.id)

@app.route('/msg/<discussion_id>')
@login_required
def msg_view(discussion_id):
    #faille de securité: on ne verifie pas que l'utilisateur fasse partie du groupe avant de l'afficher

    groups_list = models.Group.query.filter(models.Group.members.any(id=current_user.id)).all()
    current_group = models.Group.query.filter_by(id=discussion_id).first_or_404()

    #test
    #models.Message.send_message_to_group("test",current_user.id,current_group.id,None,"text")



    messages = models.Message.query.filter_by(group_recipient_id = current_group.id).all()

    for message in messages:
        message.seen_by(current_user)

    return render_template('msg.html', messages=messages, discussion = current_group,
                            discussions_list=groups_list, current_user=current_user, models=models)




@app.route('/msg/<discussion_id>', methods=['GET', 'POST'])
@login_required
def send_msg(discussion_id):


    app.logger.info("test")
    models.Message.send_message_to_group(flask.request.form.get('body'),current_user.id,discussion_id,None,"text")
    return msg_view(discussion_id)


@app.route('/new_group', methods=['GET', 'POST'])
@login_required
def new_group():
    form = NewGroupForm()
    if form.validate_on_submit() :
        current_group = models.Group.new_group(form.name.data,current_user.id,current_user.avatar,[current_user])
        flash('New Group created !')
        return msg_view(current_group.id)

    elif request.method == 'GET':

        return render_template('new_group.html', title='New Group',form=form)

@app.route('/group_settings/<group_id>', methods=['GET', 'POST'])
@login_required
def group_settings(group_id):
    form = NewGroupForm()
    if form.validate_on_submit() :
        current_group = models.Group.new_group(form.name.data,current_user.id,current_user.avatar,[current_user])
        flash('New Group created !')
        return msg_view(current_group.id)

    elif request.method == 'GET':

        return render_template('group_settings.html', title='Group Settings',form=form)


