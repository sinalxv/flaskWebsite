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
from datetime import datetime
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Flask App Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '1234bhjk256m565656hhAA##')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Flask-Mail Configuration ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER', 'rahbarysina@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS', 'yhbw okrs ogda syhn')
app.config['MAIL_DEFAULT_SENDER'] = ('Your App Name', app.config['MAIL_USERNAME'])

# --- File Upload Configuration ---
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'profile_pics')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --- Initialize Flask Extensions ---
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email_confirmed = db.Column(db.Boolean, default=False)
    first_name = db.Column(db.String(60), nullable=True)
    last_name = db.Column(db.String(60), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    avatar_url = db.Column(db.String(120), nullable=False, default='default.png')
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.email}', 'Confirmed: {self.email_confirmed}')"

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    instructor = db.Column(db.String(100), nullable=False)
    image_url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"Course('{self.title}', '{self.instructor}')"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Forms ---
class PasswordStrengthValidator:
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
        if not re.match(r'^[a-zA-Z0-9]+$', password):
            raise ValidationError('رمز عبور فقط می‌تواند شامل حروف انگلیسی (کوچک و بزرگ) و اعداد باشد.')

class RegistrationForm(FlaskForm):
    email = StringField('ایمیل', validators=[DataRequired(), Email()])
    password = PasswordField('رمز عبور', validators=[DataRequired(), PasswordStrengthValidator()])
    confirm_password = PasswordField('تکرار رمز عبور', validators=[DataRequired(), EqualTo('password', message='رمز عبور و تکرار آن باید یکسان باشند.')])
    submit = SubmitField('ثبت نام')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
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
        if not User.query.filter_by(email=email.data).first():
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

# --- Admin Forms ---
class AdminUserEditForm(FlaskForm):
    email = StringField('ایمیل', render_kw={"readonly": True})
    first_name = StringField('نام', validators=[Optional(), Length(max=60)])
    last_name = StringField('نام خانوادگی', validators=[Optional(), Length(max=60)])
    is_admin = BooleanField('ادمین')
    email_confirmed = BooleanField('تایید ایمیل')
    submit = SubmitField('ذخیره')

class AdminCourseForm(FlaskForm):
    title = StringField('عنوان', validators=[DataRequired(), Length(max=200)])
    instructor = StringField('مدرس', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('توضیحات', validators=[DataRequired()])
    image_url = StringField('آدرس تصویر', validators=[Optional(), Length(max=255)])
    submit = SubmitField('ذخیره')

# --- Helper Functions ---
def send_email(to, subject, template):
    msg = Message(subject, recipients=[to], html=template, sender=app.config['MAIL_DEFAULT_SENDER'])
    try:
        mail.send(msg)
        return True
    except Exception as e:
        logging.error(f"Error sending email to {to}: {e}", exc_info=True)
        return False

# --- Decorators ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            flash('دسترسی فقط برای مدیران مجاز است.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---
@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html', title='خانه')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('profile_dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            user = User(email=form.email.data, email_confirmed=False)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()

            token = s.dumps(form.email.data, salt='email-confirm')
            confirm_url = url_for('confirm_email', token=token, _external=True)
            html = render_template('email/confirm_email.html', confirm_url=confirm_url, user_email=form.email.data)
            if send_email(form.email.data, 'تایید ایمیل خود در برنامه ما', html):
                flash('حساب شما با موفقیت ایجاد شد! لطفاً ایمیل خود را برای تأیید بررسی کنید.', 'success')
            else:
                flash('حساب شما ایجاد شد، اما در ارسال ایمیل تأیید خطایی رخ داد.', 'warning')
            return redirect(url_for('login'))
        except Exception as e:
            logging.error(f"Registration error: {e}", exc_info=True)
            flash(f'خطای داخلی سرور: {e}', 'danger')
    return render_template('register.html', title='ثبت نام', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile_dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            if not user.email_confirmed:
                flash('لطفاً ابتدا ایمیل خود را تأیید کنید.', 'warning')
                return redirect(url_for('login'))
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('با موفقیت وارد شدید!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('profile_dashboard'))
        else:
            flash('ورود ناموفق. لطفاً ایمیل و رمز عبور خود را بررسی کنید.', 'danger')
    return render_template('login.html', title='ورود', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('شما از حساب کاربری خود خارج شدید.', 'info')
    return redirect(url_for('home'))

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
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
                flash('در ارسال ایمیل بازنشانی رمز عبور خطایی رخ داد.', 'danger')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', title='بازنشانی رمز عبور', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('profile_dashboard'))
    try:
        email = s.loads(token, salt='reset-password', max_age=3600)
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
    return redirect(url_for('profile_dashboard'))

@app.route('/profile/dashboard')
@login_required
def profile_dashboard():
    # Dummy data
    total_courses = 5
    overall_progress = 75
    latest_course_title = "مقدمه ای بر برنامه نویسی پایتون"
    new_messages = 2
    return render_template('profile/dashboard.html', title='پیشخوان کاربری', total_courses=total_courses,
                           overall_progress=overall_progress, latest_course_title=latest_course_title, new_messages=new_messages)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def profile_edit():
    form = ProfileEditForm()
    if form.validate_on_submit():
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.phone_number = form.phone_number.data
        current_user.bio = form.bio.data
        if form.avatar.data:
            try:
                filename = current_user.email.split('@')[0] + '.png'
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                form.avatar.data.save(filepath)
                current_user.avatar_url = filename
            except Exception as e:
                logging.error(f"Error saving avatar for user {current_user.email}: {e}", exc_info=True)
                flash('خطا در آپلود تصویر پروفایل.', 'danger')
                db.session.rollback()
        db.session.commit()
        flash('اطلاعات پروفایل با موفقیت به‌روزرسانی شد.', 'success')
        return redirect(url_for('profile_edit'))
    elif request.method == 'GET':
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.phone_number.data = current_user.phone_number
        form.bio.data = current_user.bio
    avatar_path = url_for('static', filename=f'profile_pics/{current_user.avatar_url}')
    return render_template('profile/edit.html', title='ویرایش پروفایل', form=form, avatar_path=avatar_path)

@app.route('/profile/courses')
@login_required
def profile_courses():
    courses = [{"title": "دوره 1", "progress": 40}, {"title": "دوره 2", "progress": 70}, {"title": "دوره 3", "progress": 100}]
    return render_template('profile/courses.html', title='دوره‌های من', courses=courses)

@app.route('/profile/orders')
@login_required
def profile_orders():
    orders = [{"id": 1, "course_title": "دوره 1", "amount": 100, "status": "پرداخت شده"},
              {"id": 2, "course_title": "دوره 2", "amount": 150, "status": "در حال پردازش"},
              {"id": 3, "course_title": "دوره 3", "amount": 200, "status": "پرداخت شده"}]
    return render_template('profile/orders.html', title='سفارشات من', orders=orders)

@app.route('/profile/settings')
@login_required
def profile_settings():
    return render_template('profile/settings.html', title='تنظیمات حساب کاربری')

@app.route('/profile/help')
@login_required
def profile_help():
    return render_template('profile/help.html', title='راهنما و پشتیبانی')

@app.route('/profile/notifications')
@login_required
def profile_notifications():
    notifications = [
        {"message": "پیام خوش آمدگویی به دوره جدید", "timestamp": "2023-10-01 10:00"},
        {"message": "تاریخ شروع دوره شما تغییر کرده است", "timestamp": "2023-10-02 14:30"},
        {"message": "پاسخ جدیدی به سوال شما در انجمن داده شده است", "timestamp": "2023-10-03 09:15"}
    ]
    return render_template('profile/notifications.html', title='اعلانات', notifications=notifications)

@app.route('/profile/favorites')
@login_required
def profile_favorites():
    return render_template('profile/favourites.html', title='علاقه‌مندی‌ها', favorites=[])

@app.route('/profile/tickets')
@login_required
def profile_tickets():
    return render_template('profile/tickets.html', title='تیکت‌های پشتیبانی', tickets=[])

# --- Admin Panel Routes ---
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = AdminUserEditForm(obj=user)
    if form.validate_on_submit():
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.is_admin = form.is_admin.data
        user.email_confirmed = form.email_confirmed.data
        db.session.commit()
        flash('کاربر با موفقیت ویرایش شد.', 'success')
        return redirect(url_for('admin_users'))
    return render_template('admin/edit_user.html', form=form)

@app.route('/admin/users/delete/<int:user_id>')
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('امکان حذف مدیر وجود ندارد.', 'danger')
    else:
        db.session.delete(user)
        db.session.commit()
        flash('کاربر حذف شد.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/courses')
@login_required
@admin_required
def admin_courses():
    courses = Course.query.order_by(Course.created_at.desc()).all()
    return render_template('admin/courses.html', courses=courses)

@app.route('/admin/courses/add', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_course():
    form = AdminCourseForm()
    if form.validate_on_submit():
        course = Course(
            title=form.title.data,
            instructor=form.instructor.data,
            description=form.description.data,
            image_url=form.image_url.data
        )
        db.session.add(course)
        db.session.commit()
        flash('دوره جدید اضافه شد.', 'success')
        return redirect(url_for('admin_courses'))
    return render_template('admin/edit_course.html', form=form, course=None)

@app.route('/admin/courses/edit/<int:course_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_course(course_id):
    course = Course.query.get_or_404(course_id)
    form = AdminCourseForm(obj=course)
    if form.validate_on_submit():
        course.title = form.title.data
        course.instructor = form.instructor.data
        course.description = form.description.data
        course.image_url = form.image_url.data
        db.session.commit()
        flash('دوره با موفقیت ویرایش شد.', 'success')
        return redirect(url_for('admin_courses'))
    return render_template('admin/edit_course.html', form=form, course=course)

@app.route('/admin/courses/delete/<int:course_id>')
@login_required
@admin_required
def admin_delete_course(course_id):
    course = Course.query.get_or_404(course_id)
    db.session.delete(course)
    db.session.commit()
    flash('دوره حذف شد.', 'success')
    return redirect(url_for('admin_courses'))

# --- Error Handlers ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

# --- Static Files Route ---
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)