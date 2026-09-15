from flask import Flask, render_template, render_template_string, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from flask_mail import Mail, Message
from datetime import datetime, timezone, timedelta
import os, secrets, string, math, re

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chicosafe.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER']         = 'smtp.gmail.com'
app.config['MAIL_PORT']           = 587
app.config['MAIL_USE_TLS']        = True
app.config['MAIL_USERNAME']       = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD']       = os.environ.get('MAIL_APP_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = ('Chico Safe', os.environ.get('MAIL_USERNAME', ''))

db        = SQLAlchemy(app)
mail      = Mail(app)
login_mgr = LoginManager(app)
login_mgr.login_view    = 'login'
login_mgr.login_message = 'Please log in to access this page.'

# Models
class User(UserMixin, db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    fernet_key    = db.Column(db.String(200), nullable=False)
    is_verified   = db.Column(db.Boolean, default=False)
    otp_code      = db.Column(db.String(6), nullable=True)
    otp_expiry    = db.Column(db.DateTime, nullable=True)
    last_login    = db.Column(db.DateTime, nullable=True)
    created_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    passwords     = db.relationship('SavedPassword', backref='owner', lazy=True, cascade='all, delete-orphan')

    def set_password(self, pw):   self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)
    def get_fernet(self):         return Fernet(self.fernet_key.encode())
    def display_name(self):       return self.username.capitalize()

    def generate_otp(self):
        self.otp_code   = ''.join(secrets.choice(string.digits) for _ in range(6))
        self.otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
        return self.otp_code

    def verify_otp(self, code):
        if not self.otp_code or not self.otp_expiry: return False
        expiry = self.otp_expiry
        if expiry.tzinfo is None: expiry = expiry.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expiry: return False
        return self.otp_code == code


class SavedPassword(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    site_name     = db.Column(db.String(100), nullable=False)
    site_username = db.Column(db.String(100), nullable=True)
    encrypted     = db.Column(db.Text, nullable=False)
    notes         = db.Column(db.Text, nullable=True)
    created_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def decrypt(self, fernet): return fernet.decrypt(self.encrypted.encode()).decode()
    def days_old(self):
        now = datetime.now(timezone.utc)
        c   = self.created_at
        if c.tzinfo is None: c = c.replace(tzinfo=timezone.utc)
        return (now - c).days


@login_mgr.user_loader
def load_user(uid): return db.session.get(User, int(uid))


# Helpers
def analyze_password(pw):
    length     = len(pw)
    has_upper  = bool(re.search(r'[A-Z]', pw))
    has_lower  = bool(re.search(r'[a-z]', pw))
    has_digit  = bool(re.search(r'\d', pw))
    has_symbol = bool(re.search(r'[^A-Za-z0-9]', pw))
    pool = (26 if has_upper else 0)+(26 if has_lower else 0)+(10 if has_digit else 0)+(32 if has_symbol else 0)
    entropy = length * math.log2(pool) if pool > 0 else 0
    score = 0; tips = []
    if length >= 8:  score += 1
    else: tips.append('Use at least 8 characters')
    if length >= 12: score += 1
    else: tips.append('Aim for 12+ characters')
    if has_upper: score += 1
    else: tips.append('Add uppercase letters (A-Z)')
    if has_lower: score += 1
    else: tips.append('Add lowercase letters (a-z)')
    if has_digit: score += 1
    else: tips.append('Add numbers (0-9)')
    if has_symbol: score += 1
    else: tips.append('Add symbols (!@#$%)')
    if score <= 2:   strength, color = 'Very Weak',  '#e74c3c'
    elif score == 3: strength, color = 'Weak',        '#e67e22'
    elif score == 4: strength, color = 'Fair',        '#f1c40f'
    elif score == 5: strength, color = 'Strong',      '#2ecc71'
    else:            strength, color = 'Very Strong', '#27ae60'
    return dict(strength=strength, color=color, score=score, max=6,
                entropy=round(entropy,1), length=length,
                has_upper=has_upper, has_lower=has_lower,
                has_digit=has_digit, has_symbol=has_symbol, tips=tips)


def generate_password(length=16, upper=True, lower=True, digits=True, symbols=True):
    chars = ''; required = []
    if upper:   chars += string.ascii_uppercase;  required.append(secrets.choice(string.ascii_uppercase))
    if lower:   chars += string.ascii_lowercase;  required.append(secrets.choice(string.ascii_lowercase))
    if digits:  chars += string.digits;           required.append(secrets.choice(string.digits))
    if symbols:
        sym = '!@#$%^&*'; chars += sym; required.append(secrets.choice(sym))
    if not chars: chars = string.ascii_letters + string.digits
    rest = [secrets.choice(chars) for _ in range(length - len(required))]
    pw = required + rest
    secrets.SystemRandom().shuffle(pw)
    return ''.join(pw)


def send_otp(user):
    code = user.generate_otp()
    db.session.commit()
    # Load HTML email template
    try:
        with open(os.path.join(app.root_path, 'templates', 'email_otp.html'), 'r', encoding='utf-8') as f:
            html_body = f.read()
        html_body = html_body.replace('{{username}}', user.display_name())
        html_body = html_body.replace('{{otp_code}}', code)

        msg = Message(
            subject='Your Chico Safe Verification Code',
            recipients=[user.email],
            html=html_body,
            body=f"Hello {user.display_name()},\n\nYour Chico Safe verification code is: {code}\n\nThis code expires in 10 minutes.\n\nIf you did not create a Chico Safe account, please ignore this email.\n\nChico Safe Security Team"
        )
        mail.send(msg)
        print(f"\n[OTP SENT] Code {code} dispatched to {user.email}")
        return True
    except Exception as e:
        print(f"\n{'='*50}")
        print(f"  OTP for {user.email}: {code}")
        print(f"  (Email failed: {e})")
        print(f"{'='*50}\n")
        return True


# Auth Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username','').strip().lower()
        email    = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        confirm  = request.form.get('confirm','')
        if not all([username, email, password]):
            flash('All fields are required.', 'error')
        elif len(username) < 3:
            flash('Username must be at least 3 characters.', 'error')
        elif not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            flash('Please enter a valid email address.', 'error')
        elif len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
        elif password != confirm:
            flash('Passwords do not match.', 'error')
        elif User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
        elif User.query.filter_by(email=email).first():
            flash('An account with this email already exists.', 'error')
        else:
            key  = Fernet.generate_key().decode()
            user = User(username=username, email=email, fernet_key=key, is_verified=False)
            user.set_password(password)
            db.session.add(user); db.session.commit()
            send_otp(user)
            session['pending_user_id'] = user.id
            flash('A verification code has been sent to your email.', 'success')
            return redirect(url_for('verify_otp'))
    return render_template('register.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    uid  = session.get('pending_user_id')
    if not uid: return redirect(url_for('register'))
    user = db.session.get(User, uid)
    if not user:
        session.pop('pending_user_id', None)
        return redirect(url_for('register'))
    if request.method == 'POST':
        code = request.form.get('otp','').strip()
        if user.verify_otp(code):
            user.is_verified = True
            user.otp_code = None; user.otp_expiry = None
            db.session.commit()
            session.pop('pending_user_id', None)
            flash('Email verified! You can now log in.', 'success')
            return redirect(url_for('login'))
        flash('Invalid or expired code. Please try again.', 'error')
    return render_template('verify_otp.html', email=user.email)


@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    uid  = session.get('pending_user_id')
    if not uid: return redirect(url_for('register'))
    user = db.session.get(User, uid)
    if user:
        send_otp(user)
        flash('A new verification code has been sent to your email.', 'success')
    return redirect(url_for('verify_otp'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username','').strip().lower()
        password = request.form.get('password','')
        user     = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if not user.is_verified:
                session['pending_user_id'] = user.id
                send_otp(user)
                flash('Please verify your email first. A new code has been sent to your email.', 'info')
                return redirect(url_for('verify_otp'))
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'error')
    return render_template('login.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# App Routes
@app.route('/dashboard')
@login_required
def dashboard():
    entries   = SavedPassword.query.filter_by(user_id=current_user.id).all()
    count     = len(entries)
    expired   = sum(1 for e in entries if e.days_old() >= 90)
    f         = current_user.get_fernet()
    strengths = {'Very Weak':0,'Weak':0,'Fair':0,'Strong':0,'Very Strong':0}
    for e in entries:
        try:
            pw = e.decrypt(f)
            s  = analyze_password(pw)['strength']
            strengths[s] = strengths.get(s, 0) + 1
        except: pass
    return render_template('dashboard.html', count=count, expired=expired, strengths=strengths)


@app.route('/profile')
@login_required
def profile():
    count = SavedPassword.query.filter_by(user_id=current_user.id).count()
    return render_template('profile.html', count=count)


@app.route('/vault')
@login_required
def vault():
    sort_by = request.args.get('sort', 'date')
    search  = request.args.get('q', '').strip().lower()
    entries = SavedPassword.query.filter_by(user_id=current_user.id).all()
    f       = current_user.get_fernet()
    all_pws = []
    items   = []
    for e in entries:
        pw = e.decrypt(f)
        all_pws.append(pw)
        a = analyze_password(pw)
        items.append(dict(
            id=e.id, site=e.site_name,
            site_username=e.site_username or '',
            password=pw, notes=e.notes or '',
            created_at=e.created_at.strftime('%d %b %Y, %H:%M') if e.created_at else '',
            days_old=e.days_old(),
            strength=a['strength'], strength_color=a['color']
        ))
    from collections import Counter
    pw_counts = Counter(all_pws)
    for item in items:
        item['is_duplicate'] = pw_counts[item['password']] > 1
    if search:
        items = [i for i in items if search in i['site'].lower() or search in i['site_username'].lower()]
    if sort_by == 'name':
        items.sort(key=lambda x: x['site'].lower())
    elif sort_by == 'strength':
        order = {'Very Weak':0,'Weak':1,'Fair':2,'Strong':3,'Very Strong':4}
        items.sort(key=lambda x: order.get(x['strength'], 0))
    else:
        items.sort(key=lambda x: x['created_at'], reverse=True)
    return render_template('vault.html', items=items, sort_by=sort_by, search=search)


@app.route('/vault/add', methods=['POST'])
@login_required
def vault_add():
    site     = request.form.get('site','').strip()
    username = request.form.get('site_username','').strip()
    pw       = request.form.get('password','').strip()
    notes    = request.form.get('notes','').strip()
    if not site or not pw:
        flash('Site name and password are required.', 'error')
        return redirect(url_for('vault'))
    f   = current_user.get_fernet()
    enc = f.encrypt(pw.encode()).decode()
    db.session.add(SavedPassword(user_id=current_user.id, site_name=site,
                                  site_username=username, encrypted=enc, notes=notes))
    db.session.commit()
    flash(f'Password for "{site}" saved.', 'success')
    return redirect(url_for('vault'))


@app.route('/vault/edit/<int:eid>', methods=['GET','POST'])
@login_required
def vault_edit(eid):
    entry = SavedPassword.query.filter_by(id=eid, user_id=current_user.id).first_or_404()
    f     = current_user.get_fernet()
    if request.method == 'POST':
        entry.site_name     = request.form.get('site','').strip()
        entry.site_username = request.form.get('site_username','').strip()
        pw                  = request.form.get('password','').strip()
        entry.notes         = request.form.get('notes','').strip()
        if pw:
            entry.encrypted = f.encrypt(pw.encode()).decode()
        db.session.commit()
        flash('Credential updated.', 'success')
        return redirect(url_for('vault'))
    return render_template('vault_edit.html', entry=entry, password=entry.decrypt(f))


@app.route('/vault/delete/<int:eid>', methods=['POST'])
@login_required
def vault_delete(eid):
    entry = SavedPassword.query.filter_by(id=eid, user_id=current_user.id).first_or_404()
    db.session.delete(entry); db.session.commit()
    flash('Password deleted.', 'info')
    return redirect(url_for('vault'))


@app.route('/analyzer')
@login_required
def analyzer(): return render_template('analyzer.html')

@app.route('/api/analyze', methods=['POST'])
@login_required
def api_analyze():
    return jsonify(analyze_password(request.json.get('password','')))


@app.route('/generator')
@login_required
def generator(): return render_template('generator.html')

@app.route('/api/generate', methods=['POST'])
@login_required
def api_generate():
    d  = request.json or {}
    pw = generate_password(max(8,min(64,int(d.get('length',16)))),
                           d.get('upper',True), d.get('lower',True),
                           d.get('digits',True), d.get('symbols',True))
    return jsonify({'password':pw, **analyze_password(pw)})


@app.route('/about')
def about(): return render_template('about.html')

@app.errorhandler(404)
def not_found(e): return render_template('404.html'), 404

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
