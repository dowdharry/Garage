'''
Make sure to organize the files as follows:
Garage (folder)
|__ garage.py
|__ templates (folder)
|	|__ control.html
|	|__ login.html
|	|__ twofa.html
|	|__ create.html
|	|__ edit.html
|	|__ delete.html
|	|__ users.html
|	|__ lockout.html
|__ static (folder)
|	|__ style.css
|__ garage.db
'''
#TODO: LOW PRIORITY: RETURN HOME IF NOT LOCKED OUT OF ACCOUNT FOR locked()
#TODO: LOW PRIORITY: ADD MORE FLASH WARNINGS
#TODO: HIGH PRIORITY: CREATE FUNCTIONS FOR REPEATED CODE
#TODO: HIGH PRIORITY: MAKE IT SO YOU CAN'T DELETE CURRENT USER
#TODO: LOW PRIORITY: ADD USER LOGS TO DATABASE
#TODO: HIGH PRIORITY: BE ABLE TO HANDLE INDIVIDUAL SESSIONS



#----Importing libraries----
print('Importing libraries...')
#from gpiozero import LED
#from gpiozero import Buzzer
from datetime import datetime
from hashlib import sha256
from flask import Flask, render_template, request, flash, redirect, session
import sqlite3
import uuid
import time
import smtplib
import string
import secrets



#----Initializing global variables----
print('Initializing system...')
#red_LED = LED(15)
#green_LED = LED(17)
#buzzer = Buzzer(25)
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(16)
last_action = datetime.now()
twofa_token = [None, None]
twofa_sent_time = None



#----Program functions----
#Beeps buzzer 5 times over 5 seconds
#def beep():
#	buzzer.beep(0.5, 0.5, 5)
#
#	return

#Sends opened email to admin email
def send_opened_msg():
	# we will use Gmial accounts and SMTP protocol
	server = smtplib.SMTP_SSL( 'smtp.gmail.com', 465)

	#Get admin email login credentials from database
	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	res = cur.execute("SELECT email, password FROM adminemail")
	res_tuple = res.fetchone()
	admin_email = res_tuple[0]
	admin_pass = res_tuple[1]
	con.close()

	#Login with credentials
	server.login(admin_email, admin_pass)

	#Compile message string to print and send.
	#Ex: 'Garage door was opened at 5:50:20 PM'
	actionMessage = ''.join([ '\nGarage door was opened at ',time.strftime('%I:%M:%S %p')])
	print(actionMessage)
	server.sendmail(admin_email, admin_email, actionMessage)
	server.quit()
	print("Email sent")

	return

def send_twofa_email(user_email, username):
	# we will use Gmial accounts and SMTP protocol
	server = smtplib.SMTP_SSL( 'smtp.gmail.com', 465)

	#Get admin email login credentials from database
	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	res = cur.execute("SELECT email, password FROM adminemail")
	res_tuple = res.fetchone()
	admin_email = res_tuple[0]
	admin_pass = res_tuple[1]
	con.close()

	#Login with credentials
	server.login(admin_email, admin_pass)

	#Generates random 5 digit OTP
	numbers = string.digits
	token = ''.join(secrets.choice(numbers) for i in range(5))
	
	#Compile message string to print and send.
	#Ex: 'Garage door was opened at 5:50:20 PM'
	actionMessage = ''.join([ '\n5 digit OTP: ', token])
	server.sendmail(admin_email, user_email, actionMessage)
	server.quit()
	print("\nOTP sent to email.")

	global twofa_token
	global twofa_sent_time
	twofa_token = [username, token]
	twofa_sent_time = datetime.now()

	return



#----App routes----
#Default page, controls which page the user is sent to based on certain conditions.
#Returns login() if creds are not valid
#Returns twofa() if creds are valid
#Returns control() if logged in
@app.route('/')
def home():
	if not session.get('creds'):
		return login()
	elif not session.get('logged_in'):
		return twofa()
	elif session.get('logged_in'):
		return control()

#Renders the page used by admins to create new users
#Returns home() if not logged in or not admin
@app.route('/create')
def create():
	if (not session.get('logged_in')) or (not session.get('is_admin')):
		return home()

	return render_template('create.html')

#The action sent by an admin to create a new user
#Returns home() if not logged in or not admin
@app.route('/createuser', methods=['POST'])
def createuser():
	if (not session.get('logged_in')) or (not session.get('is_admin')):
		return home()

	#Create username, password, and email variables based on user input
	#Password uses a random 8 character alphanumeric salt
	username = request.form["username"]
	alphabet = string.ascii_letters + string.digits
	password_salt = ''.join(secrets.choice(alphabet) for i in range(8))
	password = (sha256((request.form['password'] + password_salt).encode()).hexdigest()) + ':' + password_salt
	email = request.form["email"]

	#Check if input fields are empty, if so return back to create function
	if (username == "") or (request.form['password'] == "") or (email == ""):
		flash('One or more fields are empty')
		return create()

	#Check if input repeats an already existing user
	#If so return back to create function
	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	for user in cur.execute("SELECT username, email FROM users"):
		if (user[0] == username) or (user[1] == email):
			flash('User already exists')
			con.close()
			return create()
	con.close()

	#If input is valid and user does not already exist, add user to database
	data = (str(uuid.uuid4()), username, password, email, False, False, 0)

	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	cur.execute("INSERT INTO users VALUES(?, ?, ?, ?, ?, ?, ?)", data)
	con.commit()
	con.close()
	flash("User successfully created")
	return users()

#Renders the edit user page
#Returns home if the user is not logged in as admin
@app.route('/edit')
def edit():
	if (not session.get('logged_in')) or (not session.get('is_admin')):
		return home()

	return render_template('edit.html')

#The action sent by an admin to edit a user
#Returns home() if not logged in or not admin
@app.route('/edituser', methods=['POST'])
def edituser():
	if (not session.get('logged_in')) or (not session.get('is_admin')):
		return home()

	#Create username, password, and email variables based on user input
	#Password uses a random 8 character alphanumeric salt
	old_username = request.form["old_username"]
	old_email = request.form["old_email"]
	old_password = request.form["old_password"]
	userpointer = (old_username,)
	new_username = request.form["new_username"]
	alphabet = string.ascii_letters + string.digits
	password_salt = ''.join(secrets.choice(alphabet) for i in range(8))
	new_password = (sha256((request.form['new_password'] + password_salt).encode()).hexdigest()) + ':' + password_salt
	new_email = request.form["new_email"]

	#Check if input fields are empty, if so return back to create function
	if (new_username == "") or (request.form['new_password'] == "") or (new_email == ""):
		flash('One or more fields are empty')
		return edit()

	#Check to ensure input repeats an already existing user
	#If not return back to edit function
	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	for user in cur.execute("SELECT username, email FROM users"):
		if (user[0] == old_username) and (user[1] == old_email):
			break
	else:
		flash('User does not exist')
		con.close()
		return edit()
	con.close()

	#Checks if user being edited is admin, if they are return edit()
	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	res = cur.execute("SELECT isadmin FROM users WHERE username = (?)", userpointer)
	res_tuple = res.fetchone()
	is_admin = res_tuple[0]
	con.close()

	if is_admin == True:
		flash('Cannot edit admin information')
		return edit()

	#Obtain password hash and salt from database for input user
	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	res = cur.execute("SELECT password FROM users WHERE username = (?)", userpointer)
	res_tuple = res.fetchone()
	db_full_password = res_tuple[0]
	con.close()
	password_hash=db_full_password.split(':')[0]
	password_salt=db_full_password.split(':')[1]

	#Compare hashes and take actions
	if (sha256((old_password + password_salt).encode()).hexdigest() == password_hash):
		data = (new_email, new_password, new_username, old_username)
		con = sqlite3.connect("garage.db")
		cur = con.cursor()
		cur.execute("UPDATE users SET email = (?), password = (?), username = (?) WHERE username = (?)", data)
		con.commit()
	else:
		con.close()
		flash('Password is incorrect')
		return edit()

	con.close()
	return users()

#Renders the delete user page
#Returns home if the user is not admin or logged in
@app.route('/delete')
def delete():
	if (not session.get('logged_in')) or (not session.get('is_admin')):
		return home()

	return render_template('delete.html')

#The action sent by an admin to delete a user
#Returns home() if not logged in or not admin
@app.route('/deleteuser', methods=['POST'])
def deleteuser():
	if (not session.get('logged_in')) or (not session.get('is_admin')):
		return home()

	#Create username, password, and email variables based on user input
	username = request.form["username"]
	email = request.form["email"]
	password = request.form["password"]
	userpointer = (username,)

	#Check to ensure input repeats an already existing user
	#If not return back to delete function
	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	for user in cur.execute("SELECT username, email FROM users"):
		if (user[0] == username) and (user[1] == email):
			break
	else:
		flash('User does not exist')
		con.close()
		return delete()
	con.close()

	#Checks if user being edited is admin, if they are return home()
	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	res = cur.execute("SELECT isadmin FROM users WHERE username = (?)", userpointer)
	res_tuple = res.fetchone()
	is_admin = res_tuple[0]
	con.close()

	if is_admin == True:
		flash('Cannot delete admin user')
		return delete()

	#Obtain password hash and salt from database for input user
	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	res = cur.execute("SELECT password FROM users WHERE username = (?)", userpointer)
	res_tuple = res.fetchone()
	db_full_password = res_tuple[0]
	con.close()
	password_hash=db_full_password.split(':')[0]
	password_salt=db_full_password.split(':')[1]

	#Compare hashes and take actions
	if (sha256((password + password_salt).encode()).hexdigest() == password_hash):
		con = sqlite3.connect("garage.db")
		cur = con.cursor()
		cur.execute("DELETE FROM users WHERE username = (?)", userpointer)
		con.commit()
	else:
		con.close()
		flash('Password is incorrect')
		return delete()

	con.close()
	return users()

#Renders the login page
#Returns home() if user is already logged in
@app.route('/login')
def login():
	if session.get('logged_in'):
		return home()

	return render_template('login.html')

#The action sent by users to login
#Returns home() if user is already logged in
@app.route('/loginuser', methods=['POST'])
def loginuser():
	if session.get('logged_in'):
		return home()

	##Create username and password variables based on user input
	username = request.form["username"]
	password = request.form["password"]
	userpointer = (username,)

	#Checks if username exists, if it doesnt then return home()
	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	for user in cur.execute("SELECT username FROM users"):
		if (user[0] == username):
			break
	else:
		con.close()
		flash("Incorrect Credentials")
		return home()
	con.close()

	#Checks if account linked to username is locked, if it is then return to locked page and send 2fa email
	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	res = cur.execute("SELECT islocked FROM users WHERE username = (?)", userpointer)
	res_tuple = res.fetchone()
	islocked = res_tuple[0]
	con.close()
	if (islocked == True):
		con = sqlite3.connect("garage.db")
		cur = con.cursor()
		res = cur.execute("SELECT email FROM users WHERE username = (?)", userpointer)
		res_tuple = res.fetchone()
		user_email = res_tuple[0]
		con.close()
		send_twofa_email(user_email, username)
		return locked()

	#Obtain password hash and salt from database for input user
	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	res = cur.execute("SELECT password FROM users WHERE username = (?)", userpointer)
	res_tuple = res.fetchone()
	db_full_password = res_tuple[0]
	con.close()
	password_hash=db_full_password.split(':')[0]
	password_salt=db_full_password.split(':')[1]

	#Compare hashes and take actions
	#If hashes are correct, set creds to True and set failcount to 0 for the user in the database
	#If hashes are incorrect, increment the fail count by 1 in the database
	#If fail count reaches 3, send a twofa message and send the user to the locked screen
	if (sha256((password + password_salt).encode()).hexdigest() == password_hash):
		session['creds'] = True

		con = sqlite3.connect("garage.db")
		cur = con.cursor()
		cur.execute("UPDATE users SET failcount = 0 WHERE username = (?)", userpointer)
		con.commit()
		res = cur.execute("SELECT email FROM users WHERE username = (?)", userpointer)
		res_tuple = res.fetchone()
		user_email = res_tuple[0]
		con.close()
		send_twofa_email(user_email, username)
	else:
		con = sqlite3.connect("garage.db")
		cur = con.cursor()
		res = cur.execute("SELECT failcount FROM users WHERE username = (?)", userpointer)
		res_tuple = res.fetchone()
		failcount = res_tuple[0]

		failcount += 1
		faildata = (failcount, username)
		cur.execute("UPDATE users SET failcount = (?) WHERE username = (?)", faildata)
		con.commit()

		if failcount == 3:
			cur.execute("UPDATE users SET islocked = TRUE WHERE username = (?)", userpointer)
			con.commit()
			res = cur.execute("SELECT email FROM users WHERE username = (?)", userpointer)
			res_tuple = res.fetchone()
			user_email = res_tuple[0]
			con.close()
			send_twofa_email(user_email, username)
			return locked()

		flash("Incorrect Credentials")
		con.close()

	return home()

#Renders the two factor authentication page
#Returns home() if not valid user/pass
#Returns home() if user is already logged in
@app.route('/twofa')
def twofa():
	if not session.get('creds'):
		return home()
	if session.get('logged_in'):
		return home()

	return render_template('twofa.html')

#The two factor authentication action used to login
#Returns home() if not valid user/pass
#Returns home() if user is already logged in
@app.route('/twofauser', methods=['POST'])
def twofauser():
	if not session.get('creds'):
		return home()
	if session.get('logged_in'):
		return home()

	token = request.form["token"]
	username = request.form["username"]
	twofa_input = [username, token]

	if (twofa_input == twofa_token) and (twofa_token[0] != None):
		timedelta = datetime.now() - twofa_sent_time
		if timedelta.total_seconds() <= 60:
			session['logged_in'] = True

			userpointer = (username,)
			con = sqlite3.connect("garage.db")
			cur = con.cursor()
			res = cur.execute("SELECT isadmin FROM users WHERE username = (?)", userpointer)
			res_tuple = res.fetchone()
			is_admin = res_tuple[0]
			con.close()

			if is_admin == True:
				session['is_admin'] = True
			else:
				session['is_admin'] = False
		else:
			session['creds'] = False
			flash('Incorrect token')
	else:
		session['creds'] = False
		flash('Incorrect token')
	return home()

#Renders the locked out page when a user tries to login in to a locked out account
#Returns home() if user is already logged in
@app.route('/locked')
def locked():
	if session.get('logged_in'):
		return home()

	return render_template('lockout.html')

#The action by a user to unlock a locked account
#Returns home() if user is already logged in
@app.route('/unlockuser', methods=['POST'])
def unlockuser():
	if session.get('logged_in'):
		return home()

	token = request.form["token"]
	username = request.form["username"]
	twofa_input = [username, token]

	if (twofa_input == twofa_token) and (twofa_token[0] != None):
		timedelta = datetime.now() - twofa_sent_time
		if timedelta.total_seconds() <= 60:
			userpointer = (username,)
			con = sqlite3.connect("garage.db")
			cur = con.cursor()
			cur.execute("UPDATE users SET islocked = FALSE WHERE username = (?)", userpointer)
			con.commit()
			cur.execute("UPDATE users SET failcount = 0 WHERE username = (?)", userpointer)
			con.commit()
			con.close()
			flash('Account unlocked')
		else:
			flash('Incorrect token')
	else:
		flash('Incorrect token')

	return home()

#Renders the main garage control page
#Returns home() if not logged in
@app.route('/control')
def control():
	if not session.get('logged_in'):
		return home()
	#Connect to the database and retrieve garage status
	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	res = cur.execute("SELECT status FROM garage")
	res_tuple = res.fetchone()
	status = res_tuple[0]
	con.close()

	#Render webpage as either having the garage door closed or open with the correct
	#LEDs on and off
	if status == True:
		templateData = {'status' : True}
		green_LED.on()
		red_LED.off()
	else:
		templateData = {'status' : False}
		green_LED.off()
		red_LED.on()

	return render_template('control.html', **templateData)

#The action used to open/close the garage door
#Returns home() if not logged in
@app.route('/<action>')
def action(action):
	if not session.get('logged_in'):
		return home()

	#Calculate time delta since last garage movement
	global last_action
	time_delta = datetime.now() - last_action

	#If the garage is still moving based on previous calculations tell the user to wait
	#Else change the last_action time immediately and start the action
	if time_delta.total_seconds() <= 10:
		flash('Please wait for garage to finish moving.')
	else:	
		last_action = datetime.now()

		con = sqlite3.connect("garage.db")
		cur = con.cursor()

		if action == 'open':
			#green_LED.off()
			#red_LED.on()
			#beep()
			cur.execute("UPDATE garage SET status = FALSE")
			send_opened_msg()

		elif action == 'close':
			#green_LED.on()
			#red_LED.off()
			#beep()
			cur.execute("UPDATE garage SET status = TRUE")

		con.commit()
		con.close()

	return home()

#Renders a page to list users for admins
#Returns home() if not logged in or not admin
@app.route('/users')
def users():
	if (not session.get('logged_in')) or (not session.get('is_admin')):
		return home()

	#Obtain user information from database and render it in the webpage
	key_tuple = ('username', 'email')
	users = {}
	count = 0
	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	for user_data in cur.execute("SELECT username, email FROM users"):
		username = user_data[0]
		email = user_data[1]
		users[count] = {key_tuple[x] : user_data[x] for x, _ in enumerate(user_data)}
		count += 1
	con.close()

	templateData = {'users' : users}
	return render_template('users.html', **templateData)

#Logs out the current user
@app.route('/logout')
def logout():
	session['logged_in'] = False
	session['creds'] = False
	session['is_admin'] = False
	return home()



#----Starts program----
print('Program running...')

if __name__ == "__main__":
	app.run(host='0.0.0.0', port=80)