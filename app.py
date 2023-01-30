import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""
    if request.method == 'GET':
        user_id = session.get('user_id')
        portfolio = db.execute('SELECT symbol, SUM(shares) as shares FROM purchases WHERE user_id=? GROUP BY symbol', user_id)
        invest_total = 0
        for row in portfolio:
            row['name'] = lookup(row['symbol'])['name']
            row['price'] = round(lookup(row['symbol'])['price'], 2)
            row['total'] = round(lookup(row['symbol'])['price'] * row['shares'], 2)
        for row in portfolio:
            invest_total += row['total']
        user = db.execute('SELECT username FROM users WHERE id = ?', user_id)
        cash = db.execute('SELECT cash FROM users WHERE id = ?', user_id)
        cash = round(cash[0]['cash'], 2)
        total = cash + invest_total
        return render_template('index.html', portfolio=portfolio, cash=cash, total=total, user=user)
    else:
        if not request.form.get('add_cash'):
            pass
        else:
            user_id = session.get('user_id')
            add_cash = request.form.get('add_cash')
            db.execute('UPDATE users SET cash = cash + ? WHERE id = ?', add_cash, user_id)
            return redirect('/')



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'GET':
        user_id = session.get('user_id')
        user = db.execute('SELECT username FROM users WHERE id = ?', user_id)
        cash = db.execute('SELECT cash FROM users WHERE id = ?', user_id)
        cash = cash[0]['cash']
        return render_template("buy.html", cash=cash, user=user)
    else:
        symbol = request.form.get('symbol')
        shares = request.form.get('shares')
        if not request.form.get('symbol'):
            return apology("must provide stock symbol", 403)
        elif not request.form.get('shares'):
            return apology("must provide number of shares", 403)
        elif lookup(symbol) == None:
            return apology("invalid symbol", 400)
        user_id = session.get('user_id')
        cash = db.execute('SELECT cash FROM users WHERE id = ?', user_id)
        cash = cash[0]['cash']
        sinfo = lookup(symbol)
        total = sinfo['price'] * float(shares)
        if total > cash:
            return apology("don't enaugh money", 408)
        else:
            # update cash in users
            now = datetime.datetime.now()
            new_cash = cash - total
            db.execute('UPDATE users SET cash = ? WHERE id = ?', new_cash, user_id)

            db.execute(
                'INSERT INTO purchases (user_id,  date, type, symbol, shares, PPS, total_amount) VALUES (?, ?, ?, ?, ?, ?, ? )',
                 user_id, now, 'Buy', sinfo['symbol'], shares, sinfo['price'], total)
            return redirect('/')


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session.get('user_id')
    portfolio = db.execute('SELECT * FROM purchases WHERE user_id = ?', user_id)
    user = db.execute('SELECT username FROM users WHERE id = ?', user_id)
    return render_template('history.html', portfolio=portfolio, user=user)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        user_id=session.get('user_id')
        user = db.execute('SELECT username FROM users WHERE id = ?', user_id)
        return render_template('quote.html', user=user)
    else:
        user_id=session.get('user_id')
        user = db.execute('SELECT username FROM users WHERE id = ?', user_id)
        if not request.form.get('symbol'):
            return apology("must provide stock symbol", 403)
        else:
            symbol = request.form.get('symbol')
            if lookup(symbol) == None:
                return apology("invalid symbol", 400)
            else:
                sinfo = lookup(symbol)
                return render_template('quoted.html', name=sinfo['name'], symbol=sinfo['symbol'], price=sinfo['price'], user=user )



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        if not request.form.get("username"):
            return apology("must provide username", 403)
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        us = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(us) != 0:
            return apology("username already exist", 403)
        else:
            Username = request.form.get('username')
            Password = request.form.get('password')
            Hash = generate_password_hash(Password, method='pbkdf2:sha256', salt_length=8)
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", Username, Hash)
            return redirect('/login')

    return render_template('register.html')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == 'GET':
        user_id = session.get('user_id')
        user = db.execute('SELECT username FROM users WHERE id = ?', user_id)
        portfolio = db.execute('SELECT symbol, SUM(shares) as shares FROM purchases WHERE user_id=? GROUP BY symbol', user_id)
        return render_template('sell.html', portfolio=portfolio, user=user)
    else:
        if not request.form.get("Symbol"):
            return apology("must provide symbol", 403)
        elif not request.form.get("shares"):
            return apology("must provide shares", 403)
        elif int(request.form.get("shares")) < 0:
            return apology("shares must be gt 0")
        now = datetime.datetime.now()
        user_id = session.get('user_id')
        shares = request.form.get("shares")
        sell_item = request.form.get("Symbol")
        sell_price = lookup(sell_item)['price']
        total_sell_price = sell_price * float(shares)
        user_items = db.execute('SELECT shares FROM purchases WHERE user_id = ?', user_id)
        if user_items[0]['shares'] < int(shares):
            return apology('not enaugh shares')
        else:
            shares = -(int(shares))
            db.execute('UPDATE users SET cash = cash + ? WHERE id = ?', total_sell_price, user_id)
            db.execute('INSERT INTO purchases (user_id,  date, type, symbol, shares, PPS, total_amount) VALUES (?, ?, ?, ?, ?, ?, ? )',
            user_id, now, 'sell', sell_item, shares, sell_price, total_sell_price
            )
            return redirect('/')

