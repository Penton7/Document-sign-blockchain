import random
import string
import requests, json
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required,
                                get_jwt_identity, get_raw_jwt, get_jti, get_jwt_claims)
from flask_restful import Resource

from models import UserModel, Logging, AppToken, RevokedTokenModel, Documents, Role
from werkzeug.security import safe_str_cmp
from werkzeug.utils import secure_filename
from flask import jsonify, make_response, request, flash, redirect, url_for
import hashlib
import yagmail
import config
from datetime import datetime, date, timedelta
import os
import re
from stellar_sdk import Server, Asset, Keypair, TransactionBuilder, Network


def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()

class Auth(Resource):
    def post(self):
        if not request.is_json:
            return jsonify({"msg": "Missing JSON in request"}), 400
        username = request.json.get('username')
        password = request.json.get('password')
        print(username, password)

        if UserModel.find_by_username(username) == None:
            return make_response(jsonify({'msg': 'User Not Found'.format(username)}), 401)

        user = UserModel.find_by_username(username)
        password = hashlib.md5(password.encode())
        password = password.hexdigest()

        if user == None:
            return make_response(jsonify({"msg": "User Not Found"}), 401)
        if not username:
            return make_response(jsonify({"msg": "Missing username parameter"}), 401)
        if not password:
            return make_response(jsonify({"msg": "Missing password parameter"}), 401)

        if user and not safe_str_cmp(user.password, password):
            return make_response(jsonify({"msg": "Incorrect password"}), 401)

        if user and safe_str_cmp(user.password, password):
            access_token = create_access_token(identity=username)
            permissions = Role.find_by_role(user.roles).permissions
            public_key = UserModel.find_by_username(username).public_key
            print(public_key)
            log = Logging(
                user=username,
                logs="User Authorized",
                date=datetime.now()
            )
            (get_jwt_identity(), "authorized")
            log.save_log_to_db()
            return make_response(jsonify({ "data": {
                "status": "login",
                "permissions": permissions,
                "name": "admin",
                "password": "dasd",
                "public_key": public_key,
                "avatar": "https://icon-library.com/images/avatar-icon-images/avatar-icon-images-4.jpg",
                "token": "Bearer {0}".format(access_token)},
                "code": 200
            }), 200)

class UserInfo(Resource):
    @jwt_required
    def get(self):
        user_jwt = request.args.get('token')
        print(user_jwt)
        public_key = UserModel.find_by_username(get_jwt_identity()).public_key
        print(public_key)
        print(get_jwt_identity())
        return make_response(jsonify({ "data": {
                "name": "admin",
                "avatar": "https://icon-library.com/images/avatar-icon-images/avatar-icon-images-4.jpg",
                "public_key": public_key
            }, "code": 200}), 200)

class Logout(Resource):
    def post(self):
        return make_response(jsonify({ "data": {
                "name": "admin",
                "avatar": "https://icon-library.com/images/avatar-icon-images/avatar-icon-images-4.jpg",

            }, "code": 200}), 200)

class UserRegistration(Resource):
    def post(self):
        if not request.is_json:
            return make_response(jsonify({"msg": "Missing JSON in request"}), 400)
        data = request.json.get('data')
        secret = data['secret_key']
        if secret != config.secret_key:
            return make_response(jsonify({"msg": "Secret Key Invalid"}), 400)

        username = data['username']
        password = data['password']

        if UserModel.find_by_username(username):
            return {'message': 'User {} already exists'.format(username)}

        if username == None:
            return make_response(jsonify({"msg": "Data not found"}), 400)

        password = hashlib.md5(password.encode())
        password = password.hexdigest()
        new_user = UserModel(
            username=username,
            password=password,
            roles="user"
        )

        try:
            new_user.save_to_db()
            access_token = create_access_token(identity=username)
            permissions = Role.find_by_role("user").permissions
            # refresh_token = create_refresh_token(identity=data['username'])
            log = Logging(
                user=username,
                logs="User Registered",
                date=datetime.now()
            )
            (get_jwt_identity())
            log.save_log_to_db()
            return {
                'msg': 'User was created',
                'permissions': permissions,
                'access_token': access_token
                # 'refresh_token': refresh_token
            }
        except:
            return {'message': 'Something went wrong'}, 500

class DocumentSign(Resource):
    def post(self):
        private_key = request.json.get("private_key")
        doc_hash = request.json.get("doc_hash")
        alice_keypair = Keypair.from_secret(private_key)
        root_address = "GA3DHQSWCW5ATI7Y724TBZWHFLGUYQLLQX66WQF2TDR7M72R2F6NTIUR"

        server = Server("https://horizon-testnet.stellar.org")
        alice_account = server.load_account(alice_keypair.public_key)
        base_fee = server.fetch_base_fee()
        transaction = (
            TransactionBuilder(
                source_account=alice_account,
                network_passphrase=Network.TESTNET_NETWORK_PASSPHRASE,
                base_fee=base_fee,
            )
                .add_return_hash_memo(doc_hash)
                .append_payment_op(root_address, Asset.native(), "1")
                .build()
        )
        transaction.sign(alice_keypair)
        response = server.submit_transaction(transaction)
        print(response)
        memo_tx = response["memo"]
        tx_hash = response["id"]
        doc_sign = Documents.sign_to_db(doc_hash, tx_hash)
        return make_response(jsonify({ "memo": memo_tx,
                                       "tx_hash": tx_hash,
                                       "doc_sign": doc_sign,
                                      "code": 200}), 200)

class UserDocuments(Resource):
    @jwt_required
    def get(self):
        # user = UserModel.find_by_username(get_jwt_identity())
        # print(str(user))
        # print(get_jwt_identity())
        # documents = Documents.find_by_username(user)
        return make_response(jsonify({ "data": {
                "items": Documents.return_documents(get_jwt_identity())
            }, "code": 200}), 200)

    @jwt_required
    def post(self):
        file = request.files['file']
        filename = secure_filename(file.filename)
        file.save(os.path.join('docx/', filename))
        document_hash = sha256sum('docx/{0}'.format(filename))
        print(document_hash)
        doc_save = Documents(
            document_name=str(filename),
            author=get_jwt_identity(),
            doc_hash=document_hash,
            sign=False
        )
        doc_save.save_to_db()
        return jsonify({ "data": {
            "msg": "ok",
            "hash": document_hash,
            "file_name": filename
        }, "code": 200
        })

class Logs(Resource):
    @jwt_required
    def get(self):
        user = UserModel.find_by_username(get_jwt_identity())
        permissions = Role.find_by_role(user.roles).permissions
        if "logs" not in permissions:
            return make_response(jsonify({""
                                          "msg": "Permission denied"}), 401)
        page = 1
            #request.args['page']
        per_page = 99999
            #request.args['per_page']
        return make_response(jsonify({ "data": {
                "items": Logging.return_all(int(page), int(per_page))[0]
            }, "code": 200}), 200)

class AppTokens(Resource):
    @jwt_required
    def get(self):
        return AppToken.return_all()

    @jwt_required
    def post(self):
        data = request.json.get('data')
        name = data["name"]
        timelife = data['timelife']
        d = date.fromisoformat(timelife)
        then = datetime(d.year, d.month, d.day)
        delta = datetime.now() - then
        access_token = create_access_token(identity=name, expires_delta=timedelta(days=-delta.days))
        apptoken = AppToken(
            Name=name,
            Token=access_token,
            TimeLife=d
        )
        apptoken.save_log_to_db()
        log = Logging(
            user=get_jwt_identity(),
            logs="Create Token For {}".format(name),
            date=datetime.now()
        )
        log.save_log_to_db()
        return jsonify({"msg": "token created",
                        "app": name,
                        "access_token": access_token})

class RevokedToken(Resource):
    @jwt_required
    def post(self):
        token = request.json.get("token")
        jti = get_jti(token)
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'msg': 'Access token has been revoked'}
        except:
            return {'msg': 'Something went wrong'}, 500

class Permissions(Resource):
    @jwt_required
    def get(self):
        user = UserModel.find_by_username(get_jwt_identity())
        permissions = Role.find_by_role(user.roles).permissions
        return permissions

class Roles(Resource):
    @jwt_required
    def get(self):
        roles_list = Role.return_all()
        return roles_list

    @jwt_required
    def post(self):
        data = request.json.get('data')
        role_name = data["roleName"]
        permissions = data["permissions"]
        new_role = Role(
            name=role_name,
            permissions=permissions
        )
        new_role.save_to_db()
        return jsonify({
            "msg":"ok"})

    @jwt_required
    def put(self):
        data = request.json.get('data')
        role_name = data["role_name"]
        permissions = data["permissions"]
        Role.edit_role(role_name, permissions)
        return jsonify("yeah")

class Files(Resource):
    @jwt_required
    def get(self):
        user = UserModel.find_by_username(get_jwt_identity())
        permissions = Role.find_by_role(user.roles).permissions
        if "admin_panel" not in permissions:
            return make_response(jsonify({""
                                          "msg": "Permission denied"}), 401)
        arr = os.listdir("docx/")
        return jsonify({
            "files": arr
        })

    def post(self):
        file = request.files['file']
        filename = secure_filename(file.filename)
        file.save(os.path.join('docx/', filename))
        return jsonify({
            "msg": "ok",
            "file_name": filename
        })

    @jwt_required
    def delete(self):
        user = UserModel.find_by_username(get_jwt_identity())
        permissions = Role.find_by_role(user.roles).permissions
        if "admin_panel" not in permissions:
            return make_response(jsonify({""
                                          "msg": "Permission denied"}), 401)
        file_name = json.loads(request.data)
        file_remove = os.path.join('docx/', file_name["file_name"])
        os.remove(file_remove)
        return jsonify({
            "msg": "delete"
        })