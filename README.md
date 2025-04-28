# JWKS-Server-Project3

Project 3 - CSCE 3550
About
This project is a JWKS server.
It encrypts private keys, allows user registration, creates JWT tokens, logs authentication requests, and limits how many tokens can be requested.

How to Run
Set the environment variable:

ruby
Copy
Edit
$env:NOT_MY_KEY="your-32-character-secret-key"
Start the server:

nginx
Copy
Edit
python Project3.py
Run the tests:

nginx
Copy
Edit
python test_project3.py
Endpoints
POST /register — Register a new user and get a random password.

POST /auth — Get a JWT token.

POST /auth?expired=true — Get a token signed with an expired key.

GET /.well-known/jwks.json — Get public keys.

Files
Project3.py — Main server code

test_project3.py — Test script

screenshots/ — Screenshots showing tests and Gradebot results

README.md — This file

Requirements
Install packages:

nginx
Copy
Edit
pip install cryptography argon2-cffi pyjwt requests
Requires Python 3.8 or higher.

Notes
Set NOT_MY_KEY every time before starting the server.

Only 10 /auth requests are allowed per second.

Auth logs are saved in the database.

Faik Gokturk
