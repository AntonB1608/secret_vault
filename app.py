from flask import Flask, request, render_template, session, redirect
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import datetime as dt
from dotenv import load_dotenv
import os
from flask_wtf.csrf import CSRFProtect

load_dotenv()
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
csrf = CSRFProtect(app)

db = SQLAlchemy(app)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    trys = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

@app.route("/register", methods=["POST", "GET"])
def register():
    sonderzeichen = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        password_again = request.form["repeat_password"]
        if len(username) > 20:
            return render_template("register.html", fehlermeldung="username too long")
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            
            return render_template("register.html", fehlermeldung = "Username already taken", password=password)

        if len(password) < 15:
            return render_template("register.html", fehlermeldung = "password to short", username=username)
        has_sonderzeichen = any(zeichen in password for zeichen in sonderzeichen)
        if not has_sonderzeichen:
            return render_template("register.html", fehlermeldung = "password doesn't contain sonderzeichen", username=username)
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        
        if password == password_again:
            new_user = User(username=username, password_hash=password_hash)
            db.session.add(new_user)           
            db.session.commit()
            return redirect("/vault")
        else:
            return render_template("register.html", fehlermeldung = "passwords dont match", username=username, password=password)
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
            return render_template("login.html", fehlermeldung = "User not found")
        if user.locked_until and current_date_time < user.locked_until:
            return render_template("login.html", fehlermeldung=f"You are blocked until {user.locked_until}")
        if user.locked_until and current_date_time > user.locked_until:
            user.trys = 0
            db.session.commit()
        if bcrypt.checkpw(password.encode("utf-8"), user.password_hash):
            user.locked_until = None
            session["username"] = username
            db.session.commit()
            return redirect("/vault")
        
        user.trys += 1
        if user.trys >= 5: 
            user.locked_until = dt.datetime.today() + dt.timedelta(minutes=15)
            db.session.commit()
            return render_template("login.html", fehlermeldung=f"wrong password, you are blocked until {user.locked_until}", username=username)            
        db.session.commit()
        return render_template("login.html", fehlermeldung="wrong password", username=username)
    else:
        return render_template("login.html")
@app.route("/vault", methods = ["GET"])
def vault():
    if "username" not in session:
        return render_template("login.html")
    else:
        return render_template("vault.html", username=session["username"])
@app.route("/logout", methods = ["GET"])
def logout():      
    session.pop("username", None)
    return redirect("/login")
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5555, debug=True)