from flask import Flask, request, render_template
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import datetime as dt

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
db = SQLAlchemy(app)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    trys = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

@app.route("/register", methods=["POST", "GET"])
def register():
    sonderzeichen = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
    if request.method == "POST":
        username = request.form["username"]
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            return "Username already taken"
        password = request.form["password"]

        if len(password) < 15:
            return("password to short")
        has_sonderzeichen = any(zeichen in password for zeichen in sonderzeichen)
        if not has_sonderzeichen:
            return("password doesn't contain sonderzeichen")

        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)           
        db.session.commit()
        return username
    else:
        return render_template("register.html")
@app.route("/login", methods=["POST", "GET"])
def login():
    current_date_time = dt.datetime.today()
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if not user:
            return "User not found"
        if user.locked_until and current_date_time < user.locked_until:
            return f"You are blocked until {user.locked_until}"
        if user.locked_until and current_date_time > user.locked_until:
            user.trys = 0
        if bcrypt.checkpw(password.encode("utf-8"), user.password_hash):
            user.locked_until = None
            db.session.commit()
            return "login successful"
        if not bcrypt.checkpw(password.encode("utf-8"), user.password_hash):
            if not user.trys < 5:
                return("Wrong password, try again")
            else:
                user.locked_until = dt.datetime.today() + dt.timedelta(minutes=15)
                db.session.commit()
                return "wrong password"
    else:
        return render_template("login.html")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5555, debug=True)