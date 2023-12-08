from flask import Flask, request, redirect, url_for, jsonify, Response, send_file
from urllib.parse import quote, unquote
from functools import wraps
import matplotlib.pyplot as plt
import pandas as pd
import requests
import jwt
import json
import os

from jwt.exceptions import DecodeError
from hashing import hash_three, verified, generate_salt
from models import mydb

app = Flask(__name__)
port = int(os.environ.get('PORT', 5500))
app.config['SECRET_KEY'] = os.urandom(24)


# Auth
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        username = request.args.get('username')
        if not token or not username:
            return jsonify({"error": "authorization token is missing."}), 401
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user_id= data["user_id"]
        except DecodeError:
            return jsonify({"error": "authorization token is invalid."}), 401
        return f(current_user_id, *args, **kwargs)
    return decorated

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    cursor1 = mydb.cursor()
    username = request.args.get('username')
    password = request.args.get('password')
    if username is None or password is None:
        return jsonify("Please provide a valid username and password."), 403
    script_get = "SELECT * FROM users WHERE username =%s"
    cursor1.execute(script_get, (username,))
    user_row = cursor1.fetchone()
    if user_row is None:
        return jsonify("Your account does not exist."), 403
    hashpass = user_row[1]
    salt = user_row[2]
    if verified(username, password, salt, hashpass):
        token = jwt.encode({"username" : username}, ["SECRET_KEY"], algorithm="HS256")
        return redirect(url_for('index')+"?username="+username+"&token="+token)
    return jsonify("You're not authorized to use this feature."), 401

# register
@app.route("/signup", methods=["GET", "POST", "PUT"])
def signup():
    cursor2 = mydb.cursor()
    username = request.args.get('username')
    password = request.args.get('password')
    if not username or not password:
        return jsonify("Please enter a username and a password!"), 400
    
    script = "SELECT username FROM users WHERE username=%s"
    cursor2.execute(script, (username,))
    old_user = cursor2.fetchone()
    if old_user is not None:
        return jsonify("This username already exists!"), 400
    mydb.commit()
    salt = str(generate_salt())
    hashed = hash_three(username, password, salt)
    script_input = "INSERT INTO users(username, hashpass, salt) VALUES (%s, %s, %s)"
    cursor2.execute(script_input, (username, hashed, salt))
    mydb.commit()
    return jsonify("You have successfully signed up."), 200


# Movie Category Graph
@app.route("/category_graph", methods=["GET", "POST"])
@token_required
def category_graph():
    path = "https://tubes-tst-production.up.railway.app"
    endpoint = "/user/login"
    username = "zetalucu"
    password = "123123"
    url_request_token = path + endpoint + "?username=" + username + "&password=" + password
    rtoken = requests.post(url_request_token)
    json_rtoken = rtoken.json()
    token = json_rtoken["Token"]
    
    endpoint = "/moviecategory/"
    url_request_stats = path + endpoint + "?token=" + token
    rstats = requests.get(url_request_stats)
    rjson = rstats.json()

    df_category = pd.DataFrame(columns=["categoryId", "movieId"])
    for item in rjson:
        df_category = df_category.append(
            {
                "categoryId" : item,
                "movieId" : rjson[item]["movieId"], 
            }, 
            ignore_index=True
        )
    df_category.plot()
    plt.savefig("stats_category.png")
    return send_file("stats_category.png", mimetype="image/png")

#------------------------------------
# Movie History Graph
@app.route("/history_graph", methods=["GET", "POST"])
@token_required
def history_graph():
    path = "https://tubes-tst-production.up.railway.app"
    endpoint = "/user/login"
    username = "zetalucu"
    password = "123123"
    url_request_token = path + endpoint + "?username=" + username + "&password=" + password
    rtoken = requests.post(url_request_token)
    json_rtoken = rtoken.json()
    token = json_rtoken["Token"]
    
    endpoint = "/history/"
    url_request_stats = path + endpoint + "?token=" + token
    rstats = requests.get(url_request_stats)
    rjson = rstats.json()

    df_history = pd.DataFrame(columns=["movieName", "historyId"])
    for item in rjson:
        df_history = df_history.append(
            {
                "movieName" : item,
                "historyId" : rjson[item]["historyId"], 
            }, 
            ignore_index=True
        )
    df_history.plot()
    plt.savefig("stats_history.png")
    return send_file("stats_history.png", mimetype="image/png")

# Index
@app.route("/")
@token_required
def index():
    token = request.args.get("token")
    return jsonify(f"Hello, user! \n here's your token: {token} \n Please save this for temporary use."), 200

if __name__ == "__main__":
    app.run()

