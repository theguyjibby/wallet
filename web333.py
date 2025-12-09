
from encrypt_decrypt import encrypt_message, decrypt_message
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
from web3 import Web3
from eth_account import Account as EthAccount
from flask import Flask, render_template, request, jsonify, session, url_for,redirect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from eth_account.hdaccount import generate_mnemonic
from create_new_account import derive_account
from send_crypto_currency import send_crypto, check_balance, get_eth_price_usd
from tokens import TOKENS, ERC20_ABI
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime




app = Flask(__name__, template_folder='templates', static_folder='static')
from flask_cors import CORS
CORS(app, supports_credentials=True)

# Allow OAuth over HTTP for local testing (only if set in .env)
if os.getenv('OAUTHLIB_INSECURE_TRANSPORT'):
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///web33.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False


mail = Mail(app)

S = URLSafeTimedSerializer(app.config['SECRET_KEY'])

#seeting up google authentication
oauth = OAuth(app)
google = oauth.register(
    name="myApp",
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://oauth2.googleapis.com/token',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    client_kwargs={'scope': 'openid email profile'},
)




EthAccount.enable_unaudited_hdwallet_features()



db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    user_id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(150), nullable=False)
    lastname = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    country = db.Column(db.String(100), nullable=False)
    user_mnemonic = db.Column(db.String(250), nullable=False, unique=True)
    google_id = db.Column(db.String(200), nullable=True, unique=True)

    def get_id(self):
        return str(self.user_id)
    

class Account(db.Model, UserMixin):
    account_id= db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(150), nullable=False)
    private_key = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    account_name = db.Column(db.String(150), nullable=False)

class Transactions(db.Model, UserMixin):
    transaction_id = db.Column(db.Integer, primary_key=True)
    from_address = db.Column(db.String(150), nullable=False)
    to_address = db.Column(db.String(150), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    crypto_currency = db.Column(db.String(50), nullable=False)
    tx_hash = db.Column(db.String(150), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    is_sent = db.Column(db.Boolean, default=True)

    



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        firstname = data.get("firstname")
        lastname = data.get("lastname")
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        phone = data.get("phone")
        country = data.get("country")

        mnemonic = generate_mnemonic(12, "english")
        encrypted_mnemonic = encrypt_message(mnemonic, password)


        if not (firstname and lastname and username and email and password and phone and country):
            return jsonify({'status': 'error', 'message': 'Please fill out all fields.'})

        if User.query.filter_by(email=email).first():
            return jsonify({'status': 'error', 'message': 'User already exists. please login.'}),400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'status': 'error', 'message': 'Username already taken. please choose another one.'}),400
        
        if len(password) < 6:
            return jsonify({'status': 'false', 'message': 'Password must be at least 6 characters long!'}), 400
       
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(firstname=firstname, lastname=lastname, username=username, email=email, password=hashed_password, phone=phone, country=country, user_mnemonic=encrypted_mnemonic)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'User registered successfully.', 'mnemonic': mnemonic}),200
    return render_template('register.html')




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        if not email and not password:
            return jsonify({'status': 'error', 'message': 'Please enter email and password.'}), 400


        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return jsonify({'status': 'success', 'message': 'Login successful.'}), 200
        return jsonify({'status': 'error', 'message': 'Invalid email or password.'}), 400
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



#registration  has to be done manually but user can login via google if email exists in db
@app.route('/login/google')
def google_auth_route():
    redirect_uri = url_for("google_login_callback", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/login/google/callback")
def google_login_callback():
    try:
        token = google.authorize_access_token()
        user_info = google.parse_id_token(token, None)
    except Exception as e:
        print(f"Login Error: {e}")
        return jsonify({'status': 'error', 'message': f'Login failed: {str(e)}. Try clearing cookies or ensuring you are using 127.0.0.1 consistently.'}), 400

    # 1. Look up user by email
    user = User.query.filter_by(email=user_info['email']).first()

    if user:
        # 2. If user exists, link Google ID if not already linked
        if not user.google_id:
            user.google_id = user_info['sub']
            db.session.commit()
        
        # 3. Log the user in
        login_user(user)
        return redirect(url_for('dashboard'))    
    
    return jsonify({'status': 'error', 'message': 'User not registered. Please register first.'}), 400



@app.route('/forgot_password', methods=['POST', 'GET'])
def forgot_password_route():
    if request.method == 'POST':
        from reset_password import send_reset_email
        data = request.get_json()
        email = data.get("email")
        user = User.query.filter_by(email=email).first()
        if user:
            send_reset_email(user)

            return jsonify({"message": "click the link sent to your email"})

        return jsonify({"message": "wrong email."}), 400
    return render_template('forgot_password.html')




@app.route("/reset_password/<token>", methods=['POST', 'GET'])
def reset_token_route(token):
    from reset_password import verify_reset_token
    email = verify_reset_token(token)
    if not email:
        return jsonify({"error": "Invalid or expired token"}), 400
    if request.method == 'POST':
        data = request.get_json()
        new_password = generate_password_hash(data.get('password'))

        user = User.query.filter_by(email=email).first()
        user.password = new_password
        db.session.commit()
        return jsonify({"message": "Password updated!"})
    
    return render_template('reset_password.html', token=token)
    






@login_required
@app.route('/create_account', methods=['POST', 'GET'])
def create_account_route():
    if request.method == 'POST':
        data = request.get_json()
        account_name = data.get('account_name')
        password = data.get('password')

        verify_user = check_password_hash(current_user.password, password)
        if not verify_user:
            return jsonify("wrong password try again"), 400
        
        existing_account_name = Account.query.filter_by(account_name=account_name, user_id=current_user.user_id).first()
    
        if existing_account_name:
            return {'status': 'error', 'message': 'Account name already exists.'}, 400
    
        encrypted_mnemonic = current_user.user_mnemonic
        decrypted_mnemonic = decrypt_message(encrypted_mnemonic, password)
        Account_address, Account_private_key = derive_account(decrypted_mnemonic, Account.query.filter_by(user_id=current_user.user_id).count())
        encrypted_private_key = encrypt_message(Account_private_key, password)
   
    
    
        new_account = Account(address=Account_address, private_key=encrypted_private_key, user_id=current_user.user_id, account_name=account_name)
        db.session.add(new_account)
        db.session.commit()
        return {'status': 'success', 'address': Account_address, 'message': 'Account successfully created.'}
    return render_template('create_account.html')


@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)



@app.route('/accounts', methods=['GET'])
@login_required
def get_accounts():
    user_accounts = Account.query.filter_by(user_id=current_user.user_id).all()
    accounts_list = [{'account_id': acct.account_id, 'address': acct.address, 'account_name': acct.account_name} for acct in user_accounts]
    for acct in accounts_list:
        balance = check_balance(acct['address'])
        acct['balance'] = str(balance)
    return jsonify(accounts_list)



@app.route('/accounts/<int:account_id>', methods=['GET'])
@login_required
def get_account(account_id):
    acct = Account.query.filter_by(account_id=account_id, user_id=current_user.user_id).first()
    if not acct:
        return jsonify({'status': 'error', 'message': 'Account not found.'}), 404
    balance = check_balance(acct.address)
    
    return jsonify({'account_id': acct.account_id, 'address': acct.address, 'account_name': acct.account_name, "balance": str(balance)})


@app.route('/send_crypto', methods=['POST', 'GET'])
@login_required
def send_crypto_route():
    if request.method == 'POST':
        data = request.get_json()
        from_address = data.get('from_address')
        to_address = data.get('to_address')
        crypto_currency = data.get('crypto_currency')
        amount = float(data.get('amount'))
        password = data.get('password')
        
        confirming_to_address = Account.query.filter_by(address=to_address).first()
        if not confirming_to_address:
            return jsonify({'status': 'error', 'message': 'Recipient address not found.'}), 404
        if not Web3.is_address(to_address):
            return jsonify({'status': 'error', 'message': 'Invalid recipient address.'}), 400
        if amount == None or float(amount) <= 0:
            return jsonify({'status': 'error', 'message': 'Invalid amount.'}), 400
        
        if not check_password_hash(current_user.password, password):
            return jsonify("wrong password try again")
        
        sender_private_key = decrypt_message(Account.query.filter_by(address=from_address, user_id=current_user.user_id).first().private_key, password)
        try:
            if crypto_currency.upper() == 'ETH':
                tx_hash = send_crypto(from_address, sender_private_key, to_address, amount, crypto_currency='ETH')
            else:
                token_info = TOKENS.get(crypto_currency.upper())
                if not token_info:
                    return jsonify({'status': 'error', 'message': 'Unsupported cryptocurrency.'}), 400
                tx_hash = send_crypto(from_address, sender_private_key, to_address, amount, crypto_currency=crypto_currency.upper(), token_address=Web3.to_checksum_address(token_info['address']), token_abi=ERC20_ABI)
            
            new_transaction = Transactions(
                from_address=from_address,
                to_address=to_address,
                amount=amount,
                crypto_currency=crypto_currency.upper(),
                tx_hash=tx_hash,
                user_id=current_user.user_id,
                is_sent=True
            )
            db.session.add(new_transaction)
            
            # Since we only allow sending to internal accounts (checked above),
            # clearly create the "Received" record for the recipient immediately.
            recipient_transaction = Transactions(
                from_address=from_address,
                to_address=to_address,
                amount=amount,
                crypto_currency=crypto_currency.upper(),
                tx_hash=tx_hash,
                user_id=confirming_to_address.user_id,
                is_sent=False
            )
            db.session.add(recipient_transaction)
            
            db.session.commit()
            return jsonify({'status': 'success', 'tx_hash': tx_hash, 'message': 'Transaction sent successfully.', "amount": amount, "to_address": to_address, "balance": str(check_balance(from_address)), "crypto_currency": crypto_currency.upper()})
        except Exception as e:
            error_message = str(e)
            if "Insufficient balance" in error_message:
                return jsonify({'status': 'error', 'message': error_message}), 400
            return jsonify({'status': 'error', 'message': error_message}), 500
    return render_template('send_crypto.html')


@login_required
@app.route("/transaction_history", methods=["GET", "POST"])
def transaction_history_route():
    if request.method == "GET":
        transactions = Transactions.query.filter_by(user_id=current_user.user_id).order_by(Transactions.timestamp.desc()).all()
        transactions_list = []
        for tx in transactions:
            from_acc = Account.query.filter_by(user_id=current_user.user_id, address=tx.from_address).first()
            to_acc = Account.query.filter_by(user_id=current_user.user_id, address=tx.to_address).first()
            
            transactions_list.append({
                "transaction_id": tx.transaction_id,
                "from_address": tx.from_address,
                "from_account_name": from_acc.account_name if from_acc else "External",
                "to_address": tx.to_address,
                "to_account_name": to_acc.account_name if to_acc else "External",
                "amount": tx.amount,
                "crypto_currency": tx.crypto_currency,
                "tx_hash": tx.tx_hash,
                "timestamp": tx.timestamp,
                "is_sent": getattr(tx, 'is_sent', True) # Handle legacy records if any
            })
        
        return jsonify(transactions_list)


@app.route('/history', methods=['GET'])
@login_required
def history_page():
    return render_template('transaction_history.html', name=current_user.username)


@app.route('/get_eth_price_usd', methods=['GET'])
def get_eth_price_usd_route():
    return jsonify(get_eth_price_usd())




if __name__ == '__main__':
    with app.app_context():
        db.create_all()


    app.run(debug=False)



















