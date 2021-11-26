from run import db
from flask import jsonify
import json
import sys
class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(120), nullable=True)
    roles = db.Column(db.String(120), db.ForeignKey('role.name'),  nullable=False)
    public_key = db.Column(db.String(120))

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()


    @classmethod
    def edit_user_role(cls, username, role):
        user = cls.query.filter_by(username=username).first()
        user.roles = role
        db.session.commit()
        return jsonify({
            "msg": "Role Edited"
        })

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'username': x.username,
                'role': x.roles
            }

        return {'users': list(map(lambda x: to_json(x), UserModel.query.all()))}

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}


class Logging(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.Text())
    logs = db.Column(db.Text())
    date = db.Column(db.Text())

    def save_log_to_db(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def newest():
        return Logging.query.order_by()

    def to_json(self):
        return {
            'user': self.user,
            'logs': self.logs,
            'date': self.date
        }
    @classmethod
    def return_all(cls, page, per_page):
        logs = Logging.newest().paginate(page, per_page, True)
        jsontasks = []
        for log in logs.items:
            jsontasks.append(log.to_json())
        return [jsontasks, logs.total]

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'msg': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'msg': 'Something went wrong'}

class AppToken(db.Model):
    __tablename__ = 'app_token'

    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.Text())
    Token = db.Column(db.Text())
    TimeLife = db.Column(db.TIMESTAMP())

    def save_log_to_db(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def newest():
        return AppToken.query.order_by()

    @classmethod
    def find_by_appname(cls, appname):
        return cls.query.filter_by(Name=appname).first()


    @classmethod
    def return_all(cls):
        def to_json(self):
            return {
                'Name': self.Name,
                'Token': self.Token,
                'TimeLife': self.TimeLife.isoformat()
            }
        return {'items': list(map(lambda x: to_json(x), AppToken.query.all()))}


    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'msg': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'msg': 'Something went wrong'}

class RevokedTokenModel(db.Model):
    __tablename__ = 'revoked_tokens'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120))

    def add(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti=jti).first()
        return bool(query)

class Documents(db.Model):
    __tablename__ = "documents"
    id = db.Column(db.Integer, primary_key=True)
    document_name = db.Column(db.String(120), unique=False, nullable=False)
    author = db.Column(db.String(120), db.ForeignKey('users.username'),  nullable=False)
    doc_hash = db.Column(db.String(120))
    tx_hash = db.Column(db.String())
    sign = db.Column(db.Boolean())

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_username(cls, author):
        return cls.query.filter_by(username=author).first()

    @classmethod
    def sign_to_db(cls, doc_hash, tx_hash):
        document = cls.query.filter_by(doc_hash=doc_hash).first()
        document.sign = True
        document.tx_hash = tx_hash
        db.session.commit()
        return [document.document_name, document.tx_hash]

    @classmethod
    def return_documents(cls, username):
        def to_json(x):
            return {
                'id': x.id,
                'document_name': x.document_name,
                'author': x.author,
                'doc_hash': x.doc_hash,
                'tx_hash': x.tx_hash,
                'sign': x.sign
            }

        data = {'item': list(map(lambda x: to_json(x),
                                  Documents.query.filter_by(author=username)))}
        return data["item"]


    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'id': x.id,
                'document_name': x.document_name,
                'author': x.author,
                'doc_hash': x.doc_hash,
                'tx_hash': x.doc_hash
            }

        return {'items': list(map(lambda x: to_json(x), Documents.query.all()))}

    @classmethod
    def delete_document(cls, doc_hash):
        try:
            document_hash = cls.query.filter_by(username=doc_hash).delete()
            db.session.commit()
            return {'message': '{} deleted'.format(document_hash)}
        except:
            return {'message': 'Something went wrong'}

    @classmethod
    def add_event(cls, username, eventId):
        try:
            user = cls.query.filter_by(username=username).first()
            if user.events != None:
                lst = user.events
                lst = json.loads(lst)
                lst.append(eventId)
                user.events = json.dumps(lst)
                db.session.commit()
            else:
                user.events = json.dumps([eventId])
                db.session.commit()
            return jsonify({
                "msg": "Event added"
            })
        except Exception as e:
            print(str(e))
            return str(e)
    @classmethod
    def add_adaptation(cls, username, eventId):
        try:
            user = cls.query.filter_by(username=username).first()
            if user.adaptationEvents != None:
                lst = user.adaptationEvents
                lst = json.loads(lst)
                lst.append(eventId)
                user.adaptationEvents = json.dumps(lst)
                db.session.commit()
            else:
                user.adaptationEvents = json.dumps([eventId])
                db.session.commit()
            return jsonify({
                "msg": "Adaptation event added"
            })
        except Exception as e:
            print(str(e))
            return str(e)

    @classmethod
    def delete_event(cls, username, eventType):
        try:
            user = cls.query.filter_by(username=username).first()
            if str(eventType) == "adaptationEvents":
                user.adaptationEvents = None
                db.session.commit()
            if str(eventType) == 'events':
                user.events = None
                db.session.commit()
        except Exception as e:
            print(str(e))
            return str(e)


    # @classmethod
    # def edit_event(cls, username, eventId):
    #     user = cls.query.filter_by(username=username).first()
    #     user.events = user.events.append(eventId)
    #     db.session.commit()
    #     return jsonify({
    #         "msg": "Event Edited"
    #     })

class Role(db.Model):
    __tablename__ = "role"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True)
    permissions = db.Column(db.JSON(), unique=False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_role(cls, name):
        return cls.query.filter_by(name=name).first()

    @classmethod
    def edit_role(cls, name, permissions):
        role_name = cls.query.filter_by(name=name).first()
        role_name.permissions = permissions
        db.session.commit()
        return "ok"

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'name': x.name,
                'permissions': x.permissions
            }

        return {'items': list(map(lambda x: to_json(x), Role.query.all()))}