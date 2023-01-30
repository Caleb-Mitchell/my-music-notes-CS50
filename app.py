import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required # , lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///mus1cnotes.db")

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Display Practice Log for Current Week AND the calendar date for current week"""

    if request.method == "GET":
        checkbox_list = []
        for i in range(1,8):
            checkbox_list.append(db.execute("SELECT state FROM checkboxes WHERE day=:day_num AND user=:user", day_num=i, user=session["user_id"]))
        day_total = 0
        for elem in checkbox_list:
            if elem:
                day_total += elem[0]["state"]

        return render_template("index.html", checkbox1 = checkbox_list[0][0]["state"],
                                             checkbox2 = checkbox_list[1][0]["state"],
                                             checkbox3 = checkbox_list[2][0]["state"],
                                             checkbox4 = checkbox_list[3][0]["state"],
                                             checkbox5 = checkbox_list[4][0]["state"],
                                             checkbox6 = checkbox_list[5][0]["state"],
                                             checkbox7 = checkbox_list[6][0]["state"],
                                             
                                             day_total = day_total)

    
    else:
        """On POST method, need to first update the state values in checkboxes database, then pass updated values to render_template"""
        # Need to get value if box is checked from index.html on submit
        checkbox_list = []
        for i in range(1,8):
            if request.form.get(f"day_check{i}") == '1':
                checkbox_list.append(request.form.get(f"day_check{i}"))
            else:
                checkbox_list.append(0)

        # Update database values to new checkbox_list values
        for i in range(1,8):
            db.execute("UPDATE checkboxes SET state=:new where day=:day_num AND user=:user", new=checkbox_list[i-1], day_num=i, user=session["user_id"])

        # Clear list and set new list from new database values
        checkbox_list = []
        for i in range(1,8):
            checkbox_list.append(db.execute("SELECT state FROM checkboxes WHERE day=:day_num AND user=:user", day_num=i, user=session["user_id"]))

        day_total = 0
        for elem in checkbox_list:
            if elem:
                day_total += elem[0]["state"]
        # Alert
        if day_total == 7:
            flash("Great job practicing this week!!!")

        return render_template("index.html", checkbox1 = checkbox_list[0][0]["state"],
                                             checkbox2 = checkbox_list[1][0]["state"],
                                             checkbox3 = checkbox_list[2][0]["state"],
                                             checkbox4 = checkbox_list[3][0]["state"],
                                             checkbox5 = checkbox_list[4][0]["state"],
                                             checkbox6 = checkbox_list[5][0]["state"],
                                             checkbox7 = checkbox_list[6][0]["state"],
                                             
                                             day_total = day_total)

@app.route("/listen")
@login_required
def listen():
    """Display Listening Recommendations by Genre"""

    return render_template("listen.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page

        # Check if this entries exist, if not, create them!
        # Create 7 state entries in checkboxes table, corresponding to session_id number
        table_check = db.execute("SELECT * FROM checkboxes WHERE user=:user", user=session["user_id"])
        if len(table_check) == 0:
            for i in range(1,8):
                db.execute("INSERT INTO checkboxes (state, day, user) VALUES (:state, :day, :user)", state=0, day=i, user=session["user_id"])


        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/metronome")
@login_required
def metronome():
    """Display Metronome Page"""

    return redirect("https://www.metronomeonline.com/")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":
        return render_template("register.html")

    # User reached route via POST (as by submitting a form via POST)
    else:

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username does not already exist
        if len(rows) == 1:
            return apology("username already registered", 403)

        # Ensure username was submitted
        elif not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)
            
        # Ensure password confirmation was submitted
        elif not request.form.get("password_confirm"):
            return apology("must provide password", 403)

        # Ensure passwords match
        elif request.form.get("password") != request.form.get("password_confirm"):
            return apology("passwords must match", 403)

        # Create hash of user password
        password = generate_password_hash(request.form.get("password"))

        # Insert the new user into 'users'
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)", \
        username=request.form.get("username"), password=password)

        # Redirect to home page
        return redirect("/")

@app.route("/reset")
@login_required
def reset():
    checkbox_list = [0 , 0 , 0 , 0 , 0 , 0 , 0]
    day_total = 0
    # Set checkboxes to unchecked, first update database values to new checkbox_list values
    for i in range(1,8):
        db.execute("UPDATE checkboxes SET state=:new where day=:day_num AND user=:user", new=0, day_num=i, user=session["user_id"])
    # Return index page with cleared check boxes
    return render_template("reset.html")



