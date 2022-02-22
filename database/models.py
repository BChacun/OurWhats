from flask_login import UserMixin
from hashlib import md5
from database.database import db
from datetime import datetime

class User(UserMixin, db.Model):
    """
    :param str email: email address of user
    :param str password: encrypted password for the user

    """
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True)
    username = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    avatar = db.Column(db.String(), default='https://www.gravatar.com/avatar/{}?d=identicon&s={}')
    authenticated = db.Column(db.Boolean, default=False)
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    def is_active(self):
        """True, as all users are active."""
        return True

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.email

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False

    def get_avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return self.avatar.format(
            digest, size)


seen_table = db.Table('seen_messages',
   db.Column('message_id', db.Integer, db.ForeignKey('messages.id')),
   db.Column('user_id', db.Integer, db.ForeignKey('user.id')))

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer(), primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_recipient_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    body = db.Column(db.String())
    answerTo_id = db.Column(db.Integer(), db.ForeignKey('messages.id'), default=None)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    msg_type = db.Column(db.String, default="text") #"text", "image", "file" or "removed"
    seen = db.relationship('User',secondary=seen_table)

    @staticmethod
    def send_message_to_group(body, sender_id, group_recipient_id, answer_to_id, msg_type):
        msg = Message(sender_id=sender_id, group_recipient_id=group_recipient_id, body=body, answer_to_id=answer_to_id,msg_type=msg_type)
        db.session.add(msg)
        db.session.commit()

    @staticmethod
    def send_message_to_user(body, sender, user_recipient, answer_to_id, msg_type):
        group =db.session.groups.query.filter(db.session.groups.members.any(sender) & db.session.groups.members.any(user_recipient) & db.session.groups.members.count()==2).first()
        #         filter à verifier, surtout au niveau du count() et de sb.session.groups
        if group is None:
            group =Group.new_group("",sender.id,"",[sender, user_recipient])
        Message.send_message_to_group(body, sender.id, group.id, answer_to_id, msg_type)

    def remove_msg(self):
        self.msg_type="removed"
        self.body=""
        self.answerTo_id=None
        db.session.add(self)
        db.session.commit()



members_table = db.Table('group_members',
   db.Column('group_id', db.Integer, db.ForeignKey('group.id')),
   db.Column('user_id', db.Integer, db.ForeignKey('user.id')))


class Group(db.Model):
    __tablename__ = 'group'
    id=db.Column(db.Integer(),primary_key=True)
    name = db.Column(db.String())
    avatar = db.Column(db.String(), default='https://www.gravatar.com/avatar/{}?d=identicon&s={}') #source de l'image ou "" pour une conversation à 2
    creator_id = db.Column(db.Integer(),db.ForeignKey('user.id'))
    members = db.relationship('User',secondary=members_table)

    def get_avatar(self, size):
        digest = md5(self.name.lower().encode('utf-8')).hexdigest()
        return self.avatar.format(
            digest, size)

    def members_count(self):
        return len(self.members)


    @staticmethod
    def new_group(name, creator_id, avatar, members=None):
        if members is None:
            members = []
        group = Group(name=name, creator_id=creator_id, avatar=avatar)
        for member in members:
            group.members.append(member)
        db.session.add(group)
        db.session.commit()
        return group

    def add_member(self,member_id):
        if not(member_id in self.members):
            self.members.append(member_id)
            db.session.add(self)
            db.session.commit()

    def remove_member(self,member_id):
        self.members.remove(member_id)
        db.session.add(self)
        db.session.commit()

    def change_avatar(self,source):
        self.avatar=source
        db.session.add(self)
        db.session.commit()

    def change_name(self,name):
        self.name=name
        db.session.add(self)
        db.session.commit()

