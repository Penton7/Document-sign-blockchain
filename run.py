from flask import Flask
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from flask import send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager, Server
from flask_restful import Api
from flask_cors import CORS
import datetime
import config
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

CORS(app, resources={r"/*": {"origins": "*"}})
jwt = JWTManager(app)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://{user}:{password}@" \
                                        "{host}:{port}/{db}".format(user=os.getenv('POSTGRES_USER'),
                                                                    password=os.getenv('POSTGRES_PASSWORD'),
                                                                    host=os.getenv('POSTGRES_HOST'),
                                                                    port=os.getenv('POSTGRES_PORT'),
                                                                    db=os.getenv('POSTGRES_DB'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']
app.config['PROPAGATE_EXCEPTIONS'] = True


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return models.RevokedTokenModel.is_jti_blacklisted(jti)


db = SQLAlchemy(app)
migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command('db', MigrateCommand)
manager.add_command('runserver', Server(host='0.0.0.0', port=5000, use_debugger=False))
manager.add_command('rundebug', Server(host='0.0.0.0', port=5000, use_debugger=True))


@app.route("/data/<file_name>", methods=['GET', 'POST'])
def getFile(file_name):
    return send_file(app.config['FOLDER'] + '/' + file_name, as_attachment=True)


import views, resources, models

api.add_resource(resources.Auth, '/user/login')
api.add_resource(resources.UserInfo, '/user/info')
api.add_resource(resources.UserDocuments, '/user/documents')
api.add_resource(resources.DocumentSign, '/document/sign')
api.add_resource(resources.Logout, '/user/logout')
api.add_resource(resources.UserRegistration, '/registration')
# api.add_resource(resources.SiteUsers, '/site-user')
api.add_resource(resources.AppTokens, '/api/v2/app-token')
api.add_resource(resources.RevokedToken, "/api/v2/revoked-token")
api.add_resource(resources.Logs, '/logs')
api.add_resource(resources.Permissions, '/permissions')
api.add_resource(resources.Roles, '/api/v2/role')

if __name__ == '__main__':
    app.config["FOLDER"] = "data"
    manager.run()
