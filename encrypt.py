from flask import Flask, request, jsonify
import hashlib
import random
import string
import json


app = Flask(__name__)


def generate_password():
    password = "".join(
        random.choices(string.ascii_lowercase + " ", k=4)
    )
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/get_password", methods=["GET"])
def get_password():
    password = "fdbf5edd051cadfb31f0428974dda5fa"
    response = jsonify({"password": password})
    with open("password.json", "w") as f:
        json.dump({"password": password}, f)
    return response



# Password parametresi alabilecek şekilde değiştirdik
def check_password(password):
    """Checks if the given password matches the stored password hash."""
    password_hash = hashlib.md5(password.encode()).hexdigest()  # şifrenin md5 ile hashlenmesi
    with open("password.json", "r") as f:
        stored_password = json.load(f).get("password")  # json dosyasındaki hash değeri alınıyor
    return password_hash == stored_password  # password eşleşiyorsa true dönüyor

# Flask route to check password using HTTP request
@app.route("/check_password", methods=["POST"])
def check_password_route():
    """Handle password checking via HTTP request."""
    data = request.get_json()
    password = data.get("password")
    if check_password(password): 
        return jsonify({"message": "Success"})
    else:
        return jsonify({"message": "Failed"})


