This is a LotteryWebApp which allows the user to create accounts, create lottery draws and then play them. The draws are
encrypted and all sensitive user info is also encrypted. The draws and users are stored in a SQL database accessed using 
Flask SQLAlchemy.

The report in Lottery App Report provides a more detailed review of the project.

This project was completed as part of the CSC2031 module 'Security and Programming Paradigms' at Newcastle University by
Renwar Karim.

To run the app, set the run configuration as Python and set the path by locating the app.py file and setting that it
as the path. Then run app.py and click the URL that is obtained when the program runs (http://127.0.0.1:)

For testing admin functionality please use the following user login details to login as Admin:
Email: admin@email.com
Password: Admin1!
PIN Key: BFB5S34STBLZCOB22K6PPYDCMZMH46OJ

There are no default users registered apart from the Admin so please create users using the 'register' page

Using the authy app is the easiest way to obtain a 2FA one time password, you set this up by entering the base32 PIN key
seen above.