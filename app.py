from flask import Flask, request, render_template
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
db = SQLAlchemy(app)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

@app.route("/register", methods=["POST", "GET"])

def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        return username
    else:
        return render_template("register.html")
@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if not user:
            return "User not found"
        if bcrypt.checkpw(password.encode("utf-8"), user.password_hash):
            return "login successful"
        else:
            return "wrong password"
    else:
        return render_template("login.html")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5555, debug=True)