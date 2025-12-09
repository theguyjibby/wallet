from flask import Flask, url_for, session, redirect
from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key')

oauth = OAuth(app)

google = oauth.register(
    "myApp",
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

@app.route('/')
def homepage():
    print('home page')
    return '<a href="/login">Log in with Google</a>'

@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/dashboard')
def authorize():
    token = google.authorize_access_token()
    session['user'] = token

    userToken = session.get('user')
    userInfo = userToken['userinfo']
    page = f'<h2>Hello {userInfo["given_name"]}</h2>'
    page += '<p><strong>Your email:</strong></p>'
    page += f'<p>{userInfo["email"]}</p>'
    return page

if __name__ == '__main__':
    app.run(debug=True)
