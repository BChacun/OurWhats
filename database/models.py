import sys

import sqlalchemy
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

    def unread_messages_count(self):
        return len(db.session.query(Message).join(Group).join(User).filter((User.id==self.id) & (sqlalchemy.not_(Message.seen.any(id=self.id)))).all())

    def unread_messages(self):
        size=0
        query=db.session.query(Message).join(Group).join(User).filter((User.id == self.id) & (Message.seen.any(id=self.id))).all()
        for message in query:
            size+=sys.getsizeof(message)
        return len(query), size_with_unit(size)


    def messages_sent(self, type):
        size = 0
        query = db.session.query(Message).filter((Message.sender_id==self.id) & (Message.msg_type==type)).all()
        for message in query:
            size += sys.getsizeof(message)
        return len(query), size_with_unit(size)

    def message_sent_notext(self):
        size_image = 0
        query_image = db.session.query(Message).filter((Message.sender_id == self.id) & (Message.msg_type == "image")).all()
        for message in query_image:
            size_image += sys.getsizeof(message)
        size_file = 0
        query_file = db.session.query(Message).filter(
            (Message.sender_id == self.id) & (Message.msg_type == "file")).all()
        for message in query_file:
            size_file += sys.getsizeof(message)
        size_removed = 0
        query_removed = db.session.query(Message).filter(
            (Message.sender_id == self.id) & (Message.msg_type == "removed")).all()
        for message in query_removed:
            size_removed += sys.getsizeof(message)
        return len(query_image)+len(query_file)+len(query_removed), size_with_unit(size_image+size_file+size_removed)

    def messages_received(self):
        size = 0       #la taille en octets
        query=db.session.query(Message).join(Group).join(User).filter((Message.sender_id!=self.id) & (Group.members.any(id=self.id))).all()
        for message in query:
            size += sys.getsizeof(message)
        return len(query), size_with_unit(size)

    def is_logged(self):
        if (datetime.utcnow() - self.last_seen).total_seconds() < 300:
            return '<i class="fa fa-circle online"></i>'
        return '<i class="fa fa-circle offline"></i>'


seen_table = db.Table('seen_messages',
   db.Column('message_id', db.Integer, db.ForeignKey('messages.id')),
   db.Column('user_id', db.Integer, db.ForeignKey('user.id')))

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer(), primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_recipient_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    body = db.Column(db.String())
    answer_to_id = db.Column(db.Integer(), db.ForeignKey('messages.id'),nullable=True, default=None)
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
        group = get_existing_discussion_or_none(sender, user_recipient)
            #db.session.groups.members.any(sender) & db.session.groups.members.any(user_recipient)).first()
        if group is None:
            group =Group.new_group("",sender.id,"",[sender, user_recipient])
        Message.send_message_to_group(body, sender.id, group.id, answer_to_id, msg_type)

    def remove_msg(self):
        self.msg_type="removed"
        self.body=""
        self.answerTo_id=None
        db.session.add(self)
        db.session.commit()

    def seen_by(self,user):
        self.seen.append(user)
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
    members = db.relationship('User', backref='groups', secondary=members_table)


    def get_avatar(self, size, current_user):
        if self.avatar=="":
            #si c'est une discussion à 2 alors self.avatar=="", et on prend l'avatar de l'autre user
            return self.get_other_user_first(current_user).get_avatar(size)

        digest = md5(self.name.lower().encode('utf-8')).hexdigest()
        return self.avatar.format(digest, size)

    def members_count(self):
        return len(self.members)

    def get_other_user_first(self,user):
        for member in self.members:
            if member != user:
                return member
        return user

    def count_not_seen_msg(self,user):
        return Group.query.join(Message,  Group.id == Message.group_recipient_id).filter_by(group_recipient_id= self.id).count() - \
               Group.query.join(Message, Group.id == Message.group_recipient_id).filter_by(group_recipient_id= self.id).where(Group.members.contains(user)).count()


    #returns the name of the group to display to the user passed in parameter
    def get_name(self,current_user):
        if self.members_count() <=2:
            return self.get_other_user_first(current_user).username
        return self.name


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



#returns a discussion with only the user the interlocutor if it exists in database, and returns None if it doesn't exist
def get_existing_discussion_or_none(user, interlocutor):
    u_groups= user.groups
    i_groups= interlocutor.groups
    for group in u_groups:
        if user!=interlocutor:
            if (group in i_groups) & (group.members_count()==2): # a tester: group in list(i_groups) ?
                return group
        else:
            if (group in i_groups) & (group.members_count()==1):
                return group
    return None

def size_with_unit(size):
    if size<1024:
        return str(size)+" bytes"
    if size<1024**2:
        return str(size)+" MB"
    if size<1024**3:
        return str(size)+" GB"
    if size<1024**4:
        return str(size)+" TB"
    #on devrait être assez large avec ça mais en théorie il faudrait un else