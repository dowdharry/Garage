This program is a very secure garage door controller that uses a web interface.
The program allows for multiple users with a single admin user account that is
manually configured into garage.db. The program allows for the admin account to 
create, edit, and delete other user accounts. Security for the 
program includes two factor authentication for all users when logging in and account 
lockout to prevent brute force attempts against accounts. The program will also 
send an email to the admin email when the garage door is opened.

NOTE: Although this application is designed in mind to control a garage door, many of
these features and designs are relevant for all types of applications and systems.
The program was also intended to originally be used with RaspberryPi, the features
specific to the RaspberryPi have been commented out.

The default admin account uses the username: roger, password:roger123
To change the username, enter these commands in the command line while in the same directory as garage.db:
	python3
	import sqlite3
	data = ('[new_username]', '3af0ee39-15a8-4d11-9017-1f74cd2d8ccc')
	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	cur.execute("UPDATE users SET username = (?) WHERE uid = (?)", data)
	con.commit()
	con.close()
To change the email enter these commands in the command line while in the same directory as garage.db:
NOTE: the password for the email, is an app password obtainable from google.
	python3
	import sqlite3
	data = ('[new_email]', '3af0ee39-15a8-4d11-9017-1f74cd2d8ccc')
	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	cur.execute("UPDATE users SET email = (?) WHERE uid = (?)", data)
	con.commit()
	data = ('[new_email]', '[new_password]')
	cur.execute("UPDATE adminemail SET email = (?), password = (?)", data)
	con.commit()
	con.close()
To change the password, enter these commands in the command line while in the same directory as garage.db:
	python3
	import sqlite3
	import secrets
	import string
	from hashlib import sha256
	alphabet = string.ascii_letters + string.digits
	password_salt = ''.join(secrets.choice(alphabet) for i in range(8))
	password = (sha256(('[new_password]' + password_salt).encode()).hexdigest()) + ':' + password_salt
	data = (password, '3af0ee39-15a8-4d11-9017-1f74cd2d8ccc')
	con = sqlite3.connect("garage.db")
	cur = con.cursor()
	cur.execute("UPDATE users SET password = (?) WHERE uid = (?)", data)
	con.commit()
	con.close()

The database contains three tables:
garage(status)
users(uid, username, password, email, isadmin, islocked, failcount)
adminemail(email, password)

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
