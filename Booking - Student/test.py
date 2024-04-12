from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
import sqlite3
from flask_bcrypt import Bcrypt
from collections import Counter

app= Flask(__name__)
flaskBcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = 'thisIsSecret'
login_manager = LoginManager(app)
login_manager.login_view="login"

#creates a user model representing the user
class User(UserMixin):
    def __init__(self, id, name, phone, email, password):
         self.id = id
         self.name = name
         self.phone = phone
         self.email = email
         self.password = password
         self.authenticated = False
         def is_active(self):
            return self.is_active()
         def is_anonymous(self):
            return False
         def is_authenticated(self):
            return self.authenticated
         def is_active(self):
            return True
         def get_id(self):
            return self.id

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register', methods=['POST'])   
def register_post():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    con = sqlite3.connect("login.db")
    curs = con.cursor()
    name= request.form['name']
    phone= request.form['Phone']
    email= request.form['email']
    password = request.form['password']
    hashedPassword=flaskBcrypt.generate_password_hash(password).decode('utf-8')
    con.execute('insert into newLogin (name,phone,email,password) VALUES (?,?,?,?)',[name,phone,email,hashedPassword])
    con.commit()
    return render_template('home.html')

@login_manager.user_loader
def load_user(user_id):
   conn = sqlite3.connect('login.db')
   curs = conn.cursor()
   curs.execute("SELECT * from newLogin where user_id = (?)",[user_id])
   lu = curs.fetchone()
   if lu is None:
      return None
   else:
      return User(int(lu[0]),lu[1],lu[2],lu[3],lu[4])

@app.route('/login', methods=['POST'])
def login_post():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    con = sqlite3.connect("login.db")
    curs = con.cursor()
    email= request.form['email']
    curs.execute("SELECT * FROM newLogin where email = (?)", [email])
    row=curs.fetchone()
    if row==None:
        flash('Please try logging in again')
        return render_template('login.html')
    user = list(row)
      
    liUser = User(int(user[0]),user[1],user[2],user[3],user[4])

    password = request.form['password']
    match = flaskBcrypt.check_password_hash(liUser.password, password)

    if match and email==liUser.email:
        login_user(liUser,remember=request.form.get('remember'))
        redirect(url_for('home'))
    else:
        flash('Please try logging in again')
        return render_template('login.html')

    return render_template('home.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/enternew')
@login_required
def new_student():
   return render_template('students.html')

@app.route('/')
@app.route('/index')
def home():
    return render_template('home.html')

@app.route('/book',methods = ['POST', 'GET'])
@login_required
def createBooking():
    if request.method == 'GET':
        return render_template('booking.html')
    elif request.method == 'POST':
        request.form.items()
        try:
            date = request.form['dateChosen']
            print(date)
            numTickets = request.form['numTickets']
            
            with sqlite3.connect("newAvailability.db") as con:
                cur = con.cursor()
                cur.execute("Select NumberOfSlots from DatesAvailable Where DatesAvailable.Date like (?)",[date])
                rows = cur.fetchall(); 
                msg="Successful Booking"
                print(rows[0][0])
                if rows[0][0]>int(numTickets):
                    print(current_user.id)
                    cur.execute("UPDATE DatesAvailable SET NumberOfSlots = NumberOfSlots-(?) Where DatesAvailable.Date LIKE (?)",(int(numTickets),date))
                    for i in range(0,int(numTickets)):
                        cur.execute("INSERT INTO bookings (userID,dateID) VALUES (?,?)",(current_user.id,date) )           
                        con.commit()    
                else:
                    flash('Date is fully booked')
        
        except Exception as e:
            msg = "error in insert operation"
            print(e)
        finally:
            return render_template("booking.html",msg = msg)

@app.route("/profile")
@login_required
def viewProfile():
    with sqlite3.connect("newAvailability.db") as con:
        cur = con.cursor()
        cur.execute("select dateID from bookings where userID = (?)",[current_user.id])
        rows = cur.fetchall(); 
        datesCount=list(Counter((rows)).items())
        print(datesCount[0])
    return render_template("profile.html",name=current_user.name,bookings=datesCount)


app.debug = True
app.run()