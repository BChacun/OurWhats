from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, validators
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, Length


class SignupForm(FlaskForm):
    email = EmailField(u'Email', validators=[validators.input_required()])
    username = StringField(u'Username', validators=[validators.input_required()])
    password = PasswordField(u'Password', validators=[validators.input_required()])
    submit = SubmitField('Submit')


class LoginForm(FlaskForm):
    username = StringField(u'Username')
    password = PasswordField(u'Password')
    submit = SubmitField('Submit')

class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    about_me = TextAreaField('About me', validators=[Length(min=0, max=140)])
    submit = SubmitField('Submit')