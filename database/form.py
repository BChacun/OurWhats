from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, validators
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, Length, ValidationError
import database.models as models


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

    def __init__(self, original_username, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_username(self, username):
        if username.data != self.original_username:
            user = models.User.query.filter_by(username=self.username.data).first()
            if user is not None:
                raise ValidationError('Please use a different username.')




class NewGroupForm(FlaskForm):
    name = StringField('name', validators=[DataRequired()])
    submit = SubmitField('Submit')

class GroupSettingsForm_ChangeName(FlaskForm):
    name = StringField('name', validators=[DataRequired()])
    submit = SubmitField('Submit')

class GroupSettingsForm_AddMember(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    submit = SubmitField('Submit')

