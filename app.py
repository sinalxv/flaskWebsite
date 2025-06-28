# app.py

from flask import Flask, render_template, redirect, url_for, flash, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, TelField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional
from flask_wtf.file import FileField, FileAllowed
from flask_mail import Mail, Message
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer
import os
import re
import logging
from datetime import datetime # For dummy data timestamps

# Configure logging to show error messages in the console with full traceback
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Flask App Configuration ---
app = Flask(__name__)
# Load SECRET_KEY from environment variable, fallback to a default (change in production!)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or '1234bhjk256m565656hhAA##'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db' # SQLite database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Disable SQLAlchemy event system tracking

# --- Flask-Mail Configuration (for sending emails) ---
# Replace these with your actual SMTP server details
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER') or 'rahbarysina@gmail.com'
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS') or 'yhbw okrs ogda syhn' # Use an App Password for Gmail
app.config['MAIL_DEFAULT_SENDER'] = ('Your App Name', app.config['MAIL_USERNAME'])

# --- File Upload Configuration ---
# Folder to store profile pictures
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'profile_pics')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16 MB max upload size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --- Initialize Flask Extensions ---

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # The login page users are redirected to
login_manager.login_message_category = 'info' # Flash message category for login required
mail = Mail(app)

# --- Configuration for secure token generation (e.g., email confirmation, password reset) ---
# We use the same SECRET_KEY for token generation
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- User Model ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email_confirmed = db.Column(db.Boolean, default=False)
    first_name = db.Column(db.String(60), nullable=True) # New field
    last_name = db.Column(db.String(60), nullable=True)  # New field
    bio = db.Column(db.Text, nullable=True)             # New field
    phone_number = db.Column(db.String(20), nullable=True) # New field
    avatar_url = db.Column(db.String(120), nullable=False, default='default.png') # New field for profile picture

    def set_password(self, password):
        """Hashes the given password and stores it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the given password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        """String representation of the User object."""
        return f"User('{self.email}', 'Confirmed: {self.email_confirmed}')"

# --- User Loader for Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    """
    This function is used by Flask-Login to load a user from the database
    given their user ID.
    """
    return User.query.get(int(user_id))

# --- Forms ---

class PasswordStrengthValidator:
    """
    Custom validator for password strength.
    Requirements:
    - Minimum 8 characters.
    - At least one uppercase English letter (A-Z).
    - At least one lowercase English letter (a-z).
    - At least one digit (0-9).
    - Only English letters (uppercase/lowercase) and digits allowed.
    """
    def __call__(self, form, field):
        password = field.data
        if len(password) < 8:
            raise ValidationError('رمز عبور باید حداقل 8 کاراکتر باشد.')
        if not re.search(r'[A-Z]', password):
            raise ValidationError('رمز عبور باید حداقل یک حرف بزرگ انگلیسی داشته باشد.')
        if not re.search(r'[a-z]', password):
            raise ValidationError('رمز عبور باید حداقل یک حرف کوچک انگلیسی داشته باشد.')
        if not re.search(r'\d', password):
            raise ValidationError('رمز عبور باید حداقل یک عدد داشته باشد.')
        # checks if password contains only English alphanumeric characters
        if not re.match(r'^[a-zA-Z0-9]+$', password):
            raise ValidationError('رمز عبور فقط می‌تواند شامل حروف انگلیسی (کوچک و بزرگ) و اعداد باشد.')


class RegistrationForm(FlaskForm):
    email = StringField('ایمیل', validators=[DataRequired(), Email()])
    password = PasswordField('رمز عبور', validators=[DataRequired(), PasswordStrengthValidator()])
    confirm_password = PasswordField('تکرار رمز عبور', validators=[DataRequired(), EqualTo('password', message='رمز عبور و تکرار آن باید یکسان باشند.')])
    submit = SubmitField('ثبت نام')

    def validate_email(self, email):
        """Checks if the email is already registered."""
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('این ایمیل قبلاً ثبت شده است. لطفاً یک ایمیل دیگر انتخاب کنید.')

class LoginForm(FlaskForm):
    email = StringField('ایمیل', validators=[DataRequired(), Email()])
    password = PasswordField('رمز عبور', validators=[DataRequired()])
    remember = BooleanField('مرا به خاطر بسپار')
    submit = SubmitField('ورود')

class RequestResetForm(FlaskForm):
    email = StringField('ایمیل', validators=[DataRequired(), Email()])
    submit = SubmitField('درخواست بازنشانی رمز عبور')

    def validate_email(self, email):
        """Checks if a user with the given email exists in the database."""
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('هیچ حسابی با این ایمیل وجود ندارد. لطفاً ابتدا ثبت نام کنید.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('رمز عبور جدید', validators=[DataRequired(), PasswordStrengthValidator()])
    confirm_password = PasswordField('تایید رمز عبور جدید', validators=[DataRequired(), EqualTo('password', message='رمز عبور و تکرار آن باید یکسان باشند.')])
    submit = SubmitField('بازنشانی رمز عبور')

class ProfileEditForm(FlaskForm):
    first_name = StringField('نام', validators=[Optional(), Length(max=60)])
    last_name = StringField('نام خانوادگی', validators=[Optional(), Length(max=60)])
    phone_number = TelField('شماره تماس', validators=[Optional(), Length(max=20)])
    bio = TextAreaField('بیوگرافی', validators=[Optional(), Length(max=500)])
    avatar = FileField('تصویر پروفایل', validators=[FileAllowed(ALLOWED_EXTENSIONS, 'فقط تصاویر (PNG, JPG, JPEG, GIF) مجاز هستند.')])
    submit = SubmitField('ذخیره تغییرات')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('رمز عبور فعلی', validators=[DataRequired()])
    new_password = PasswordField('رمز عبور جدید', validators=[DataRequired(), PasswordStrengthValidator()])
    confirm_new_password = PasswordField('تایید رمز عبور جدید', validators=[DataRequired(), EqualTo('new_password', message='رمز عبور جدید و تایید آن باید یکسان باشند.')])
    submit = SubmitField('تغییر رمز عبور')

# --- Helper Functions ---

def send_email(to, subject, template):
    """
    Helper function to send emails.
    :param to: Recipient email address
    :param subject: Email subject
    :param template: HTML content of the email (as a string)
    """
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    try:
        mail.send(msg)
        return True
    except Exception as e:
        # Log the full traceback if email sending fails
        logging.error(f"Error sending email to {to}: {e}", exc_info=True)
        return False

# --- Routes ---

@app.route('/')
@app.route('/home')
def home():
    """Main home page of the application."""
    return render_template('home.html', title='خانه')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Route for new user registration."""
    if current_user.is_authenticated:
        return redirect(url_for('profile_dashboard')) # Redirect if user is already logged in
    form = RegistrationForm()
    try:
        if form.validate_on_submit():
            email = form.email.data
            password = form.password.data
            hashed_password = generate_password_hash(password)
            user = User(email=email, password_hash=hashed_password, email_confirmed=False)
            db.session.add(user)
            db.session.commit()

            # Send confirmation email
            token = s.dumps(email, salt='email-confirm')
            confirm_url = url_for('confirm_email', token=token, _external=True)
            html = render_template('email/confirm_email.html', confirm_url=confirm_url, user_email=email)
            if send_email(email, 'تایید ایمیل خود در برنامه ما', html):
                flash('حساب شما با موفقیت ایجاد شد! لطفاً ایمیل خود را برای تأیید بررسی کنید.', 'success')
            else:
                flash('حساب شما ایجاد شد، اما در ارسال ایمیل تأیید خطایی رخ داد. لطفاً با پشتیبانی تماس بگیرید.', 'warning')
            return redirect(url_for('login'))
    except Exception as e:
        logging.error(f"Registration error: {e}", exc_info=True)
        flash(f'خطای داخلی سرور: {e}', 'danger')
    return render_template('register.html', title='ثبت نام', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Route for user login."""
    if current_user.is_authenticated:
        return redirect(url_for('profile_dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            try:
                # Check if password matches
                if user.check_password(form.password.data):
                    if not user.email_confirmed:
                        flash('لطفاً ابتدا ایمیل خود را تأیید کنید.', 'warning')
                        return redirect(url_for('login'))
                    login_user(user, remember=form.remember.data)
                    next_page = request.args.get('next')
                    flash('با موفقیت وارد شدید!', 'success')
                    return redirect(next_page) if next_page else redirect(url_for('profile_dashboard'))
                else:
                    # Password did not match
                    flash('ورود ناموفق. لطفاً ایمیل و رمز عبور خود را بررسی کنید.', 'danger')
            except Exception as e:
                # Catch any unexpected errors during password check (e.g., corrupted hash)
                logging.error(f"An unexpected error occurred during password check for user {form.email.data}: {e}", exc_info=True)
                flash('خطایی غیرمنتظره در هنگام ورود رخ داد. لطفاً با پشتیبانی تماس بگیرید.', 'danger')
        else:
            # User not found with the provided email
            flash('ورود ناموفق. لطفاً ایمیل و رمز عبور خود را بررسی کنید.', 'danger')
    return render_template('login.html', title='ورود', form=form)

@app.route('/logout')
@login_required # Only logged-in users can access this route
def logout():
    """Route for user logout."""
    logout_user()
    flash('شما از حساب کاربری خود خارج شدید.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard_old():
    """Redirects old dashboard route to new profile dashboard."""
    return redirect(url_for('profile_dashboard'))

@app.route('/confirm_email/<token>')
def confirm_email(token):
    """Route for email confirmation."""
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600) # Token valid for 1 hour
    except Exception:
        flash('لینک تأیید نامعتبر یا منقضی شده است.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user:
        if user.email_confirmed:
            flash('ایمیل شما قبلاً تأیید شده است.', 'info')
        else:
            user.email_confirmed = True
            db.session.commit()
            flash('ایمیل شما با موفقیت تأیید شد! اکنون می‌توانید وارد شوید.', 'success')
    else:
        flash('کاربری با این ایمیل یافت نشد.', 'danger')
    return redirect(url_for('login'))

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    """Route for requesting password reset."""
    if current_user.is_authenticated:
        return redirect(url_for('profile_dashboard'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(user.email, salt='reset-password')
            reset_url = url_for('reset_password', token=token, _external=True)
            html = render_template('email/reset_password.html', reset_url=reset_url, user_email=user.email)
            if send_email(user.email, 'درخواست بازنشانی رمز عبور در برنامه ما', html):
                flash('یک ایمیل با دستورالعمل‌های بازنشانی رمز عبور برای شما ارسال شد.', 'info')
            else:
                flash('در ارسال ایمیل بازنشانی رمز عبور خطایی رخ داد. لطفاً بعداً امتحان کنید.', 'danger')
        return redirect(url_for('login')) # Always redirect to login page to avoid information disclosure
    return render_template('reset_password_request.html', title='بازنشانی رمز عبور', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Route for setting a new password."""
    if current_user.is_authenticated:
        return redirect(url_for('profile_dashboard'))
    try:
        email = s.loads(token, salt='reset-password', max_age=3600) # Token valid for 1 hour
    except Exception:
        flash('لینک بازنشانی رمز عبور نامعتبر یا منقضی شده است.', 'danger')
        return redirect(url_for('reset_password_request'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('کاربری با این ایمیل یافت نشد.', 'danger')
        return redirect(url_for('reset_password_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('رمز عبور شما با موفقیت بازنشانی شد! اکنون می‌توانید وارد شوید.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', title='بازنشانی رمز عبور', form=form)

# --- Profile Routes ---

@app.route('/profile')
@login_required
def profile_redirect():
    """Redirects base /profile to /profile/dashboard."""
    return redirect(url_for('profile_dashboard'))

@app.route('/profile/dashboard')
@login_required
def profile_dashboard():
    """User Dashboard/Overview page."""
    # Dummy data for demonstration
    total_courses = 5
    overall_progress = 75 # Example percentage
    latest_course_title = "مقدمه ای بر برنامه نویسی پایتون"
    new_messages = 2

    return render_template(
        'profile/dashboard.html',
        title='پیشخوان کاربری',
        total_courses=total_courses,
        overall_progress=overall_progress,
        latest_course_title=latest_course_title,
        new_messages=new_messages
    )

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def profile_edit():
    """Edit Profile Information page."""
    form = ProfileEditForm()
    if form.validate_on_submit():
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.phone_number = form.phone_number.data
        current_user.bio = form.bio.data

        if form.avatar.data:
            # Handle avatar upload (simplified - in real app, save securely and unique names)
            filename = current_user.email.split('@')[0] + '.png' # Example: use username as filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            try:
                # Ensure the directory exists before saving
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                form.avatar.data.save(filepath)
                current_user.avatar_url = filename
            except Exception as e:
                logging.error(f"Error saving avatar for user {current_user.email}: {e}", exc_info=True)
                flash('خطا در آپلود تصویر پروفایل.', 'danger')
                db.session.rollback() # Rollback in case of file saving error

        db.session.commit()
        flash('اطلاعات پروفایل با موفقیت به‌روزرسانی شد.', 'success')
        return redirect(url_for('profile_edit'))
    elif request.method == 'GET':
        # Populate form fields with current user data on GET request
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.phone_number.data = current_user.phone_number
        form.bio.data = current_user.bio
    
    # Path to user's profile picture
    # Use url_for to correctly generate the static path
    avatar_path = url_for('static', filename='profile_pics/' + current_user.avatar_url) if current_user.avatar_url else url_for('static', filename='profile_pics/default.png')

    return render_template('profile/edit.html', title='ویرایش پروفایل', form=form, avatar_path=avatar_path)

@app.route('/profile/courses')
@login_required
def profile_courses():
    """My Courses page."""
    # Dummy data for courses
    courses = [
        {'id': 1, 'title': 'مقدمه ای بر برنامه نویسی پایتون', 'instructor': 'جاناتان دو', 'progress': 75, 'image': 'https://placehold.co/150x90/aabbcc/ffffff?text=Python'},
        {'id': 2, 'title': 'مبانی توسعه وب با Flask', 'instructor': 'سارا احمدی', 'progress': 50, 'image': 'https://placehold.co/150x90/ccddff/000000?text=Flask'},
        {'id': 3, 'title': 'طراحی دیتابیس برای مبتدیان', 'instructor': 'علی فریدون', 'progress': 90, 'image': 'https://placehold.co/150x90/ffeedd/000000?text=DB'},
        {'id': 4, 'title': 'یادگیری ماشین با پایتون', 'instructor': 'دکتر فاطمه', 'progress': 20, 'image': 'https://placehold.co/150x90/cceeff/000000?text=ML'},
    ]
    return render_template('profile/courses.html', title='دوره‌های من', courses=courses)

@app.route('/profile/orders')
@login_required
def profile_orders():
    """Order History page."""
    # Dummy data for orders
    orders = [
        {'id': 'ORD001', 'date': datetime(2023, 1, 15).strftime('%Y-%m-%d'), 'items': ['مقدمه ای بر برنامه نویسی پایتون'], 'amount': '500,000 تومان', 'status': 'تکمیل شده'},
        {'id': 'ORD002', 'date': datetime(2023, 3, 1).strftime('%Y-%m-%d'), 'items': ['مبانی توسعه وب با Flask', 'طراحی دیتابیس برای مبتدیان'], 'amount': '950,000 تومان', 'status': 'تکمیل شده'},
        {'id': 'ORD003', 'date': datetime(2023, 5, 20).strftime('%Y-%m-%d'), 'items': ['یادگیری ماشین با پایتون'], 'amount': '700,000 تومان', 'status': 'تکمیل شده'},
    ]
    return render_template('profile/orders.html', title='تاریخچه سفارشات', orders=orders)

@app.route('/profile/security', methods=['GET', 'POST'])
@login_required
def profile_security():
    """Security settings and change password page."""
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.current_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('رمز عبور شما با موفقیت تغییر کرد.', 'success')
            return redirect(url_for('profile_security'))
        else:
            flash('رمز عبور فعلی اشتباه است.', 'danger')
    return render_template('profile/security.html', title='امنیت و تغییر رمز عبور', form=form)

@app.route('/profile/favorites')
@login_required
def profile_favorites():
    """Favorites/Wishlist page."""
    # Dummy data for favorites
    favorites = [
        {'id': 5, 'title': 'ساخت اپلیکیشن موبایل با React Native', 'instructor': 'نرگس حسینی', 'image': 'https://placehold.co/150x90/ddccaa/000000?text=React+Native'},
        {'id': 6, 'title': 'اصول طراحی UI/UX', 'instructor': 'حسین کریمی', 'image': 'https://placehold.co/150x90/bbccaa/000000?text=UI/UX'},
    ]
    return render_template('profile/favorites.html', title='علاقه‌مندی‌ها', favorites=favorites)

@app.route('/profile/tickets')
@login_required
def profile_tickets():
    """Support Tickets page."""
    # Dummy data for support tickets
    tickets = [
        {'id': 'TKT001', 'subject': 'مشکل در دسترسی به دوره پایتون', 'status': 'پاسخ داده شده', 'date': datetime(2023, 6, 1).strftime('%Y-%m-%d %H:%M')},
        {'id': 'TKT002', 'subject': 'خطا در پرداخت سفارش ORD003', 'status': 'در حال بررسی', 'date': datetime(2023, 6, 10).strftime('%Y-%m-%d %H:%M')},
    ]
    return render_template('profile/tickets.html', title='تیکت‌های پشتیبانی', tickets=tickets)



# --- Database Creation (for development only) ---
# In production, use tools like Flask-Migrate for database migrations.
# with app.app_context():
#     db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
