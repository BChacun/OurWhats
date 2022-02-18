from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, validators
from wtforms.fields.html5 import EmailField


class SignupForm(FlaskForm):
    email = EmailField(u'Email', validators=[validators.input_required()])
    username = StringField(u'Username', validators=[validators.input_required()])
    password = PasswordField(u'Password', validators=[validators.input_required()])
    submit = SubmitField('Submit')


class LoginForm(FlaskForm):
    username = StringField(u'Username')
    password = PasswordField(u'Password')
    submit = SubmitField('Submit')