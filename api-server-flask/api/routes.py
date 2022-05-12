# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""
import urllib.request as request
import urllib.parse as parse
import json, math
import wolframalpha
from itertools import permutations as perm

from datetime import datetime, timezone, timedelta

from functools import wraps

from flask import request
from flask_restx import Api, Resource, fields

import jwt
import wolframalpha

from .models import db, Users, JWTTokenBlocklist
from .config import BaseConfig

rest_api = Api(version="1.0", title="Users API")

key = "T9P5X5-5AR8HT3U5R"
base_url = "https://api.wolframalpha.com/v2/query?"
client = wolframalpha.Client(key)

"""
    Flask-Restx models for api request and response data
"""

signup_model = rest_api.model('SignUpModel', {"username": fields.String(required=True, min_length=2, max_length=32),
                                              "email": fields.String(required=True, min_length=4, max_length=64),
                                              "password": fields.String(required=True, min_length=4, max_length=16)
                                              })

login_model = rest_api.model('LoginModel', {"email": fields.String(required=True, min_length=4, max_length=64),
                                            "password": fields.String(required=True, min_length=4, max_length=16)
                                            })


equation_solving_model = rest_api.model('Solving', {"equation": fields.String(required=True, min_length=1, max_length=32),
                                                   })
integration_solving_model = rest_api.model('Integration', {"function": fields.String(required=True, min_length=1, max_length=32),
                                                   })


"""
   Helper function for JWT token required
"""

def token_required(f):

    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if "authorization" in request.headers:
            token = request.headers["authorization"]

        if not token:
            return {"success": False, "msg": "Valid JWT token is missing"}, 400

        try:
            data = jwt.decode(token, BaseConfig.SECRET_KEY, algorithms=["HS256"])
            current_user = Users.get_by_email(data["email"])

            if not current_user:
                return {"success": False,
                        "msg": "Sorry. Wrong auth token. This user does not exist."}, 400

            token_expired = db.session.query(JWTTokenBlocklist.id).filter_by(jwt_token=token).scalar()

            if token_expired is not None:
                return {"success": False, "msg": "Token revoked."}, 400

            if not current_user.check_jwt_auth_active():
                return {"success": False, "msg": "Token expired."}, 400

        except:
            return {"success": False, "msg": "Token is invalid"}, 400

        return f(current_user, *args, **kwargs)

    return decorator


"""
    Flask-Restx routes
"""
@rest_api.route('/api/users/solve')
class Solve(Resource):
    """
       Creates a new user by taking 'signup_model' input
    """

    @rest_api.expect(equation_solving_model, validate=True)
    def post(self):
        req_data = request.get_json()
        equation = req_data.get("equation")
        new_equation = equation
        res = client.query(equation)
        answer = next(res.results).text
        return (answer)


################
def make_json(func_string):
    return json.loads(request.urlopen(base_url + parse.urlencode([('input', func_string), ('format', 'plaintext'), ('output', 'JSON'), ('appid', key)])).read().decode(encoding='utf-8'))

##########
      
####### trying integration ##############

@rest_api.route('/api/users/integrate')
class Integrate(Resource):
    """
       Creates a new user by taking 'signup_model' input
    """
    

    @rest_api.expect(integration_solving_model, validate=True)
    def post(self):
        req_data = request.get_json()

        func = req_data.get("function")

        res = client.query('integrate  ' + func)
        answer = next(res.results).text
        return (answer)

        #json_data = make_json(func + " " )
        #return (func)





##########################################
@rest_api.route('/api/users/register')
class Register(Resource):
    """
       Creates a new user by taking 'signup_model' input
    """

    @rest_api.expect(signup_model, validate=True)
    def post(self):

        req_data = request.get_json()

        _username = req_data.get("username")
        _email = req_data.get("email")
        _password = req_data.get("password")

        user_exists = Users.get_by_email(_email)
        if user_exists:
            return {"success": False,
                    "msg": "Email already taken"}, 400

        new_user = Users(username=_username, email=_email)

        new_user.set_password(_password)
        new_user.save()

        return {"success": True,
                "userID": new_user.id,
                "msg": "The user was successfully registered"}, 200


@rest_api.route('/api/users/login')
class Login(Resource):
    """
       Login user by taking 'login_model' input and return JWT token
    """

    @rest_api.expect(login_model, validate=True)
    def post(self):

        req_data = request.get_json()

        _email = req_data.get("email")
        _password = req_data.get("password")

        user_exists = Users.get_by_email(_email)

        if not user_exists:
            return {"success": False,
                    "msg": "This email does not exist."}, 400

        if not user_exists.check_password(_password):
            return {"success": False,
                    "msg": "Wrong credentials."}, 400

        # create access token uwing JWT
        token = jwt.encode({'email': _email, 'exp': datetime.utcnow() + timedelta(minutes=30)}, BaseConfig.SECRET_KEY)

        user_exists.set_jwt_auth_active(True)
        user_exists.save()

        return {"success": True,
                "token": token,
                "user": user_exists.toJSON()}, 200





