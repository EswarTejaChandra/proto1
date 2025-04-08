import base64
import logging
import os
import secrets
import smtplib
import time
import traceback
from datetime import datetime, timedelta
from io import BytesIO
from queue import Queue
from threading import Lock, Thread

import bcrypt
import pyotp
import qrcode
from bson import ObjectId
from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_mail import Mail, Message
from pymongo import MongoClient

from flask_session import Session

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)



def getStatusBadge(status):
    """Generate status text for booking status"""
    if status == 'cancelled':
        return f'your status: {status.replace("_", " ").capitalize()}'
    else:
        return f'{status.replace("_", " ").capitalize()}'

# Add template global functions
app.jinja_env.globals.update(getStatusBadge=getStatusBadge)

# MongoDB setup
client = MongoClient(os.getenv('MONGODB_URI', 'mongodb://localhost:27017/'))
db = client.laundry_management

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_MAX_EMAILS'] = 100
app.config['MAIL_ASCII_ATTACHMENTS'] = False

mail = Mail(app)

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('laundry_notifications.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Notification queue for handling async notifications
notification_queue = Queue()
notification_lock = Lock()

def process_notification_queue():
    """Background worker to process notification queue"""
    while True:
        try:
            notification = notification_queue.get()
            if notification is None:  # Poison pill to stop the worker
                break
                
            notification_type, data = notification
            send_notification(notification_type, data)
            notification_queue.task_done()
            
        except Exception as e:
            logger.error(f"Error processing notification: {str(e)}")
        finally:
            notification_queue.task_done()

@app.before_request
def start_notification_worker():
    """Start notification worker thread"""
    if not hasattr(app, 'notification_worker_started'):
        worker = Thread(target=process_notification_queue)
        worker.daemon = True  # Mark as daemon thread to allow proper shutdown
        worker.start()
        app.notification_worker_started = True

@app.teardown_appcontext
def cleanup_notification_worker(exception=None):
    """Clean up notification worker on shutdown"""
    notification_queue.put(None)  # Send poison pill to stop worker




def send_notification(notification_type, data):
    """Send notification based on type"""
    try:
        if notification_type == 'booking_confirmation':
            send_email(
                to=data['email'],
                subject='Booking Confirmation - ET Laundry',
                template='booking_confirmation',
                **data
            )
        elif notification_type == 'service_start':
            send_email(
                to=data['email'],
                subject='Your Laundry Service Has Started',
                template='service_start',
                **data
            )
        elif notification_type == 'service_working':
            send_email(
                to=data['email'],
                subject='Your Laundry is Being Processed',
                template='service_working',
                **data
            )
        elif notification_type == 'service_complete':
            send_email(
                to=data['email'],
                subject='Your Laundry is Ready for Collection',
                template='service_complete',
                **data
            )
        elif notification_type == 'booking_cancelled':
            send_email(
                to=data['email'],
                subject='Booking Cancellation Confirmation',
                template='cancellation_confirmation',
                **data
            )
            
        # Log successful notification
        logger.info(f"Notification sent: {notification_type} to {data['email']}")
        
    except Exception as e:
        logger.error(f"Failed to send notification {notification_type}: {str(e)}")
        # Implement retry logic here if needed

def schedule_notifications(booking):
    """Schedule all notifications for a booking"""
    try:
        # Schedule start notification
        start_time = booking['start_time']
        if start_time > datetime.now():
            delay = (start_time - datetime.now()).total_seconds()
            if delay > 0:
                Thread(target=schedule_notification, args=(
                    'service_start',
                    {
                        'email': booking['user_email'],
                        'user_name': booking['user_name'],
                        'machine': booking['machine_number'],
                        'date': booking['date'].strftime('%Y-%m-%d'),
                        'time': booking['time']
                    },
                    delay
                )).start()
        
        # Schedule working notification (30 minutes after start)
        working_time = start_time + timedelta(minutes=30)
        if working_time > datetime.now():
            delay = (working_time - datetime.now()).total_seconds()
            if delay > 0:
                Thread(target=schedule_notification, args=(
                    'service_working',
                    {
                        'email': booking['user_email'],
                        'user_name': booking['user_name'],
                        'machine': booking['machine_number']
                    },
                    delay
                )).start()
        
        # Schedule completion notification (based on duration)
        completion_time = booking['end_time']
        if completion_time > datetime.now():
            delay = (completion_time - datetime.now()).total_seconds()
            if delay > 0:
                Thread(target=schedule_notification, args=(
                    'service_complete',
                    {
                        'email': booking['user_email'],
                        'user_name': booking['user_name'],
                        'machine': booking['machine_number'],
                        'date': booking['date'].strftime('%Y-%m-%d'),
                        'time': booking['time']
                    },
                    delay
                )).start()
                
    except Exception as e:
        logger.error(f"Error scheduling notifications for booking {booking['_id']}: {str(e)}")

def schedule_notification(notification_type, data, delay):
    """Schedule a single notification after delay seconds"""
    try:
        time.sleep(delay)
        notification_queue.put((notification_type, data))
    except Exception as e:
        logger.error(f"Error scheduling notification {notification_type}: {str(e)}")

class User(UserMixin):
    def __init__(self, user_data):
        self.user_data = user_data
        self.id = str(user_data.get('_id'))
        self.email = user_data.get('email')
        self.name = user_data.get('name')
        self.password = user_data.get('password')
        self.verified = user_data.get('verified', False)
        self.mfa_enabled = user_data.get('mfa_enabled', False)
        self.mfa_secret = user_data.get('mfa_secret')
        self.preferences = user_data.get('preferences', {
            'notifications': True,
            'language': 'en',
            'theme': 'light'
        })
        self.loyalty_points = user_data.get('loyalty_points', 0)
        self.referral_code = user_data.get('referral_code')
        self.referred_by = user_data.get('referred_by')
        self.created_at = user_data.get('created_at', datetime.utcnow())
        self.last_login = user_data.get('last_login')
        self.login_history = user_data.get('login_history', [])

    @staticmethod
    def get(user_id):
        user_data = db.users.find_one({'_id': ObjectId(user_id)})
        return User(user_data) if user_data else None

    def update_preferences(self, preferences):
        self.preferences.update(preferences)
        db.users.update_one(
            {'_id': ObjectId(self.id)},
            {'$set': {'preferences': self.preferences}}
        )

    def add_loyalty_points(self, points):
        self.loyalty_points += points
        db.users.update_one(
            {'_id': ObjectId(self.id)},
            {'$set': {'loyalty_points': self.loyalty_points}}
        )

    def update_login_history(self):
        current_time = datetime.utcnow()
        self.login_history.append({
            'timestamp': current_time,
            'ip': request.remote_addr
        })
        # Keep only last 10 logins
        self.login_history = self.login_history[-10:]
        db.users.update_one(
            {'_id': ObjectId(self.id)},
            {
                '$set': {
                    'last_login': current_time,
                    'login_history': self.login_history
                }
            }
        )

@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({'_id': ObjectId(user_id)})
    return User(user_data) if user_data else None

def convert_12h_to_24h(time_str):
    """Convert 12-hour time format to 24-hour format"""
    try:
        # Split the time into hours, minutes, and AM/PM
        time_part, period = time_str.strip().split()
        hours, minutes = map(int, time_part.split(':'))

        # Convert to 24-hour format
        if period.upper() == 'PM' and hours != 12:
            hours += 12
        elif period.upper() == 'AM' and hours == 12:
            hours = 0

        return f"{hours:02d}:{minutes:02d}"
    except Exception as e:
        return None

@app.route('/')
@login_required
def home():
    # Get all bookings for current user
    bookings = list(db.bookings.find(
        {'user_id': ObjectId(current_user.id)},
        sort=[('date', 1), ('time', 1)]
    ))
    return render_template('dashboard/index.html', bookings=bookings)

def send_email(to, subject, template, **kwargs):
    """Send email with proper error handling and logging"""
    try:
        if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
            logger.error("Email credentials not configured. Please set MAIL_USERNAME and MAIL_PASSWORD environment variables.")
            return False

        msg = Message(
            subject=subject,
            recipients=[to],
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        msg.html = render_template(f'emails/{template}.html', **kwargs)
        
        # Add logging for debugging
        logger.info(f"Attempting to send email to {to} with subject: {subject}")
        
        mail.send(msg)
        logger.info(f"Email sent successfully to {to}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending email to {to}: {str(e)}")
        # Log the full error traceback
        import traceback
        logger.error(traceback.format_exc())
        return False
@app.route('/create-booking', methods=['POST'])
@login_required
def create_booking():
    try:
        # Step 1: Collect inputs
        machine = request.form.get('machine')
        date = request.form.get('date')
        time = request.form.get('time')
        duration = int(request.form.get('duration', 1))

        # Step 2: Basic validation
        if not all([machine, date, time]):
            return jsonify({'success': False, 'message': 'All fields (machine, date, time) are required.'})

        # Step 3: Convert and validate time & date
        try:
            booking_date = datetime.strptime(date, '%Y-%m-%d')
            time_24h = convert_12h_to_24h(time)  # Should be like '14:30'
            if not time_24h:
                raise ValueError("Invalid time format")
            start_time = datetime.strptime(f"{date} {time_24h}", "%Y-%m-%d %H:%M")
        except ValueError:
            return jsonify({'success': False, 'message': 'Invalid date or time format.'})

        # Step 4: Business rules check
        if start_time < datetime.now():
            return jsonify({'success': False, 'message': 'Cannot book a slot in the past.'})
        if duration > 3 or duration < 1:
            return jsonify({'success': False, 'message': 'Booking duration must be between 1 and 3 hours.'})

        end_time = start_time + timedelta(hours=duration)

        # Step 5: Check existing bookings for overlaps
        existing_bookings = db.bookings.find({
            'machine_number': int(machine),
            'date': booking_date,
            'status': {'$in': ['slot_booked', 'pending']}
        })

        for existing in existing_bookings:
            existing_start = datetime.strptime(f"{date} {convert_12h_to_24h(existing['time'])}", "%Y-%m-%d %H:%M")
            existing_end = existing_start + timedelta(hours=existing.get('duration', 1))

            # Overlap logic
            if (start_time < existing_end and end_time > existing_start):
                return jsonify({'success': False, 'message': 'Time slot overlaps with an existing booking.'})

        # Step 6: Prepare booking object
        booking = {
            'user_id': ObjectId(current_user.id),
            'user_email': current_user.user_data['email'],
            'user_name': current_user.user_data['name'],
            'machine_number': int(machine),
            'date': booking_date,
            'time': time,  # original 12-hour input
            'duration': duration,
            'start_time': start_time,
            'end_time': end_time,
            'status': 'slot_booked',
            'created_at': datetime.utcnow(),
            'notification_log': []
        }

        # Step 7: Save to DB with initial status
        booking['status'] = 'pending'
        result = db.bookings.insert_one(booking)
        if result.inserted_id:
            # Step 8: Trigger confirmation email / notification
            schedule_notifications(booking)
            notification_queue.put(('booking_confirmation', {
                'email': booking['user_email'],
                'user_name': booking['user_name'],
                'machine': booking['machine_number'],
                'date': date,
                'time': time,
                'duration': duration,
                'end_time': end_time.strftime("%I:%M %p")
            }))
            return jsonify({'success': True, 'message': 'Booking created successfully with pending status.'})

        return jsonify({'success': False, 'message': 'Failed to create booking. Please try again.'})

    except Exception as e:
        logger.exception("Exception during booking creation")
        return jsonify({'success': False, 'message': 'An unexpected error occurred. Please try again later.'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user_data = db.users.find_one({'email': email})
        if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data['password'].encode('utf-8')):
            user = User(user_data)
            login_user(user)
            user.update_login_history()
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        
        flash('Invalid email or password', 'danger')
    
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = db.users.find_one({'email': email})
        
        if user:
            # Generate 6-digit passcode
            passcode = ''.join(secrets.choice('0123456789') for _ in range(6))
            passcode_expires = datetime.utcnow() + timedelta(minutes=15)
            
            # Update user with passcode
            db.users.update_one(
                {'_id': user['_id']},
                {
                    '$set': {
                        'reset_passcode': passcode,
                        'reset_passcode_expires': passcode_expires
                    }
                }
            )
            
            # Send passcode to admin email
            try:
                admin_email = 'chowdaryet@gmail.com'
                
                msg = Message('Password Reset Passcode',
                            sender=app.config['MAIL_USERNAME'],
                            recipients=[admin_email])
                
                msg.body = f'''Password Reset Request

User Email: {email}
Passcode: {passcode}

This passcode will expire in 15 minutes.

Please forward this passcode to the user.'''

                mail.send(msg)
                flash('A passcode has been sent to the admin. Please check your email for the passcode.')
                
                # Store email in session for verification
                session['reset_email'] = email
                return redirect(url_for('verify_passcode'))
                
            except Exception as e:
                print(f"Error sending passcode email: {str(e)}")
                flash('There was an error sending the passcode. Please try again later.')
        else:
            flash('Email not found.')
        
        return redirect(url_for('login'))
    
    return render_template('auth/forgot_password.html')

@app.route('/verify-passcode', methods=['GET', 'POST'])
def verify_passcode():
    if 'reset_email' not in session:
        flash('Password reset session expired. Please start again.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        user_passcode = request.form.get('passcode')
        user = db.users.find_one({'email': session['reset_email']})
        
        if not user or 'reset_passcode' not in user:
            flash('Invalid passcode or session expired. Please start again.', 'danger')
            return redirect(url_for('forgot_password'))
            
        if user['reset_passcode_expires'] < datetime.utcnow():
            flash('Passcode has expired. Please request a new one.', 'danger')
            return redirect(url_for('forgot_password'))
            
        if user_passcode == user['reset_passcode']:
            # Passcode verified, allow password reset
            session['passcode_verified'] = True
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid passcode. Please try again.', 'danger')
            
    return render_template('auth/verify_passcode.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'passcode_verified' not in session or not session['passcode_verified']:
        flash('Please verify your passcode first.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        user = db.users.find_one({'email': session['reset_email']})
        
        if user:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            db.users.update_one(
                {'_id': user['_id']},
                {
                    '$set': {'password': hashed_password},
                    '$unset': {'reset_passcode': 1, 'reset_passcode_expires': 1}
                }
            )
            
            # Clear session variables
            session.pop('reset_email', None)
            session.pop('passcode_verified', None)
            
            flash('Password has been reset successfully.')
            return redirect(url_for('login'))
        else:
            flash('User not found.', 'danger')
            return redirect(url_for('forgot_password'))
    
    return render_template('auth/reset_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user's bookings and convert cursor to list
    bookings = list(db.bookings.find({'user_id': ObjectId(current_user.id)}))
    return render_template('dashboard/index.html', bookings=bookings)

# Add a new route to mark machine as ready and send notification
@app.route('/mark-machine-ready/<booking_id>', methods=['POST'])
@login_required
def mark_machine_ready(booking_id):
    try:
        booking = db.bookings.find_one({'_id': ObjectId(booking_id)})
        if not booking:
            return jsonify({'success': False, 'message': 'Booking not found'})
        
        # Update booking status
        db.bookings.update_one(
            {'_id': ObjectId(booking_id)},
            {'$set': {'status': 'ready'}}
        )
        
        # Get user details
        user = db.users.find_one({'_id': booking['user_id']})
        if user:
            try:
                msg = Message('Your Laundry Machine is Ready!',
                            sender=app.config['MAIL_USERNAME'],
                            recipients=[user['email']])
                
                msg.body = f'''Dear {user['name']},

Your laundry machine is now ready:
- Machine: {booking['machine_number']}
- Date: {booking['date'].strftime('%Y-%m-%d')}
- Time: {booking['time']}

Please collect your laundry promptly.

Best regards,
Laundry Management System'''

                mail.send(msg)
                
            except Exception as e:
                print(f"Error sending ready notification email: {str(e)}")
        
        return jsonify({'success': True, 'message': 'Machine marked as ready'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/cancel-booking/<booking_id>', methods=['POST'])
@login_required
def cancel_booking(booking_id):
    try:
        # Find the booking
        booking = db.bookings.find_one({
            '_id': ObjectId(booking_id),
            'user_id': ObjectId(current_user.id)
        })
        
        if not booking:
            return jsonify({
                'success': False,
                'message': 'Booking not found.'
            })
        
        # Check if booking can be cancelled
        if booking['status'] not in ['pending', 'confirmed', 'slot_booked']:
            logger.warning(f"Booking {booking_id} cannot be cancelled due to status {booking['status']}")
            return jsonify({
                'success': False,
                'message': 'This booking cannot be cancelled.'
            })
        
        # Delete booking from database
        result = db.bookings.delete_one(
            {'_id': ObjectId(booking_id)}
        )
        
        if result.deleted_count > 0:
            # Send cancellation confirmation email
            user_email = current_user.user_data.email
            user_name = current_user.user_data.name
            
            send_email(
                to=user_email,
                subject='Booking Cancellation Confirmation',
                template='cancellation_confirmation',
                user_name=user_name,
                machine=booking['machine_number'],
                date=booking['date'].strftime('%Y-%m-%d'),
                time=booking['time']
            )
            
            # Also add to notification queue for immediate UI feedback
            notification_queue.put(('booking_cancelled', {
                'email': user_email,
                'user_name': user_name,
                'machine': booking['machine_number'],
                'date': booking['date'].strftime('%Y-%m-%d'),
                'time': booking['time']
            }))
            
            return jsonify({
                'success': True,
                'message': 'Booking cancelled successfully!'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to cancel booking.'
            })
        
    except Exception as e:
        logger.error(f"Error cancelling booking: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while cancelling the booking.'
        })

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Basic validation
        if not all([name, email, password]):
            flash('All fields are required', 'danger')
            return redirect(url_for('register'))
            
        # Check if email already exists
        if db.users.find_one({'email': email}):
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
            
        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Generate verification token
        verification_token = secrets.token_urlsafe(32)
        
        # Create user
        user_data = {
            'name': name,
            'email': email,
            'password': hashed_password.decode('utf-8'),
            'verified': False,
            'verification_token': verification_token,
            'created_at': datetime.utcnow(),
            'preferences': {
                'notifications': True,
                'language': 'en',
                'theme': 'light'
            },
            'loyalty_points': 0
        }
        
        db.users.insert_one(user_data)
        
        # Send verification email
        verification_url = url_for('verify_email', token=verification_token, _external=True)
        
        msg = Message('Verify Your Email',
                     sender=app.config['MAIL_DEFAULT_SENDER'],
                     recipients=[email])
        
        msg.body = f'''Dear {name},

Please verify your email by clicking the following link:
{verification_url}

If you did not create an account, please ignore this email.

Best regards,
Laundry Management System'''
        
        mail.send(msg)
        
        flash('Registration successful! Please check your email to verify your account.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/register.html')


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Handle profile update
        name = request.form.get('name')
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        # Verify current password if trying to change password
        if new_password:
            stored_password = current_user.user_data['password']
            if isinstance(stored_password, str):
                stored_password = stored_password.encode('utf-8')
            
            if not bcrypt.checkpw(current_password.encode('utf-8'), stored_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('profile'))
            
            # Hash new password
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            db.users.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$set': {'password': hashed_password}}
            )
            flash('Password updated successfully', 'success')
        
        # Update name and email
        if name or email:
            update_data = {}
            if name:
                update_data['name'] = name
            if email:
                # Check if email is already taken
                if email != current_user.user_data['email']:
                    existing_user = db.users.find_one({'email': email})
                    if existing_user:
                        flash('Email already registered', 'danger')
                        return redirect(url_for('profile'))
                update_data['email'] = email
            
            if update_data:
                db.users.update_one(
                    {'_id': ObjectId(current_user.id)},
                    {'$set': update_data}
                )
                flash('Profile updated successfully', 'success')
                # Update current_user data
                current_user.user_data.update(update_data)
        
        return redirect(url_for('profile'))
    
    return render_template('dashboard/profile.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        problem = request.form.get('problem')
        
        # Validate required fields
        if not all([name, email, problem]):
            flash('All fields are required', 'danger')
            return redirect(url_for('contact'))
            
        # Validate email format
        if '@' not in email or '.' not in email.split('@')[-1]:
            flash('Please enter a valid email address', 'danger')
            return redirect(url_for('contact'))
        
        # Create contact document
        contact_data = {
            'name': name,
            'email': email,
            'problem': problem,
            'created_at': datetime.utcnow()
        }
        
        try:
            # Insert into contacts collection
            db.contacts.insert_one(contact_data)
            
            # Send email notification to admin
            msg = Message('New Contact Form Submission',
                        sender=app.config['MAIL_USERNAME'],
                        recipients=['chowdaryet@gmail.com'])
            
            msg.subject = f"New Contact Form Submission from {name}"
            msg.body = f"""Name: {name}
Email: {email}
Message:
{problem}"""
            
            mail.send(msg)
            
            flash('Thank you for your message. We will get back to you soon!', 'success')
            return redirect(url_for('contact'))
            
        except Exception as e:
            logger.error(f"Error processing contact form: {str(e)}")
            logger.error(traceback.format_exc())
            flash('Sorry, we couldn\'t send your message right now. Please try again later.', 'danger')
    
    return render_template('contact.html')

@app.route('/enable-mfa', methods=['GET', 'POST'])
@login_required
def enable_mfa():
    if request.method == 'POST':
        code = request.form.get('code')
        if current_user.mfa_secret and pyotp.TOTP(current_user.mfa_secret).verify(code):
            db.users.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$set': {'mfa_enabled': True}}
            )
            flash('MFA enabled successfully!', 'success')
            return redirect(url_for('profile'))
        flash('Invalid verification code', 'error')
    
    # Generate new secret if not exists
    if not current_user.mfa_secret:
        secret = pyotp.random_base32()
        db.users.update_one(
            {'_id': ObjectId(current_user.id)},
            {'$set': {'mfa_secret': secret}}
        )
        current_user.mfa_secret = secret
    
    # Generate QR code
    totp = pyotp.TOTP(current_user.mfa_secret)
    provisioning_uri = totp.provisioning_uri(
        current_user.email,
        issuer_name="ET Laundry"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_code = base64.b64encode(buffered.getvalue()).decode()
    
    return render_template('dashboard/mfa.html', qr_code=qr_code, secret=current_user.mfa_secret)

@app.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    user_data = db.users.find_one({'verification_token': token})
    if user_data and user_data.get('verification_token_expires') > datetime.utcnow():
        db.users.update_one(
            {'_id': user_data['_id']},
            {'$set': {'verified': True}, '$unset': {'verification_token': 1, 'verification_token_expires': 1}}
        )
        flash('Email verified successfully!', 'success')
        return redirect(url_for('login'))
    flash('Invalid or expired verification token', 'error')
    return redirect(url_for('login'))

@app.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    code = request.form.get('code')
    user_id = session.get('user_id')
    if user_id:
        user_data = db.users.find_one({'_id': ObjectId(user_id)})
        if user_data and user_data.get('mfa_secret'):
            if pyotp.TOTP(user_data['mfa_secret']).verify(code):
                user = User(user_data)
                login_user(user)
                user.update_login_history()
                return redirect(url_for('home'))
    flash('Invalid verification code', 'error')
    return redirect(url_for('login'))

# Add a route to update booking status
@app.route('/update-booking-status/<booking_id>', methods=['POST'])
@login_required
def update_booking_status(booking_id):
    try:
        new_status = request.form.get('status')
        if not new_status:
            return jsonify({
                'success': False,
                'message': 'Status is required.'
            })
        
        # Find the booking
        booking = db.bookings.find_one({
            '_id': ObjectId(booking_id),
            'user_id': ObjectId(current_user.id)
        })
        
        if not booking:
            return jsonify({
                'success': False,
                'message': 'Booking not found.'
            })
        
        # Update booking status
        result = db.bookings.update_one(
            {'_id': ObjectId(booking_id)},
            {
                '$set': {
                    'status': new_status,
                    'last_updated': datetime.now()
                }
            }
        )
        
        if result.modified_count > 0:
            # Log the status change
            logger.info(f"Booking {booking_id} status updated to {new_status}")
            
            # Send appropriate notification based on new status
            if new_status == 'started':
                notification_queue.put(('service_start', {
                    'email': booking['user_email'],
                    'user_name': booking['user_name'],
                    'machine': booking['machine_number'],
                    'date': booking['date'].strftime('%Y-%m-%d'),
                    'time': booking['time']
                }))
            elif new_status == 'working':
                notification_queue.put(('service_working', {
                    'email': booking['user_email'],
                    'user_name': booking['user_name'],
                    'machine': booking['machine_number']
                }))
            elif new_status == 'completed':
                notification_queue.put(('service_complete', {
                    'email': booking['user_email'],
                    'user_name': booking['user_name'],
                    'machine': booking['machine_number'],
                    'date': booking['date'].strftime('%Y-%m-%d'),
                    'time': booking['time']
                }))
            
            return jsonify({
                'success': True,
                'message': f'Booking status updated to {new_status}.'
            })
        
        return jsonify({
            'success': False,
            'message': 'Failed to update booking status.'
        })
        
    except Exception as e:
        logger.error(f"Error updating booking status: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while updating the booking status.'
        })

# Start notification worker thread
notification_worker = Thread(target=process_notification_queue, daemon=True)
notification_worker.start()

if __name__ == '__main__':
    app.run(debug=True)