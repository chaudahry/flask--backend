# app.py (main Flask application file)
from flask import Flask, request, jsonify, send_from_directory, make_response, render_template
from flask_cors import CORS
import os
import json
import uuid
import zipfile
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
import random
from email.message import EmailMessage
from dotenv import load_dotenv # Import load_dotenv

# Import Appwrite client
from appwrite.client import Client
from appwrite.services.users import Users
from appwrite.services.databases import Databases
from appwrite.services.storage import Storage
from appwrite.query import Query
from appwrite.exception import AppwriteException
from appwrite.input_file import InputFile



from mimetypes import guess_type

# Load environment variables from .env file
load_dotenv()
print("Loaded ENV:")
print("APPWRITE_ENDPOINT:", os.environ.get("APPWRITE_ENDPOINT"))
print("APPWRITE_PROJECT_ID:", os.environ.get("APPWRITE_PROJECT_ID"))
print("SMTP_USER:", os.environ.get("SMTP_USER"))


# Import your NLP processing modules (assuming these exist)
# Ensure these modules are available in your Render environment
from text_extractor import extract_text_from_file
from text_processor import preprocess_text, \
    extract_skills_from_text, categorize_resume
from resume_matcher import calculate_match_score_enhanced


app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

# --- Database (Appwrite Integration) ---
APPWRITE_ENDPOINT = os.environ.get("APPWRITE_ENDPOINT")
APPWRITE_PROJECT_ID = os.environ.get("APPWRITE_PROJECT_ID")
APPWRITE_API_KEY = os.environ.get("APPWRITE_API_KEY") # For server-side operations

APPWRITE_DATABASE_ID = os.environ.get("APPWRITE_DATABASE_ID")
APPWRITE_COLLECTION_USERS_ID = os.environ.get("APPWRITE_COLLECTION_USERS_ID")
APPWRITE_COLLECTION_JOB_REQUIREMENTS_ID = os.environ.get("APPWRITE_COLLECTION_JOB_REQUIREMENTS_ID")
APPWRITE_COLLECTION_RESUMES_ID = os.environ.get("APPWRITE_COLLECTION_RESUMES_ID")
APPWRITE_COLLECTION_SCREENING_RESULTS_ID = os.environ.get("APPWRITE_COLLECTION_SCREENING_RESULTS_ID")
APPWRITE_BUCKET_RESUMES_ID = os.environ.get("APPWRITE_BUCKET_RESUMES_ID")


appwrite_client = None
appwrite_users = None
appwrite_databases = None
appwrite_storage = None

if not APPWRITE_ENDPOINT or not APPWRITE_PROJECT_ID or not APPWRITE_API_KEY:
    print("WARNING: Appwrite environment variables are not fully set. Appwrite features will not work.")
else:
    try:
        appwrite_client = Client()
        appwrite_client.set_endpoint(APPWRITE_ENDPOINT) \
                       .set_project(APPWRITE_PROJECT_ID) \
                       .set_key(APPWRITE_API_KEY)

        appwrite_users = Users(appwrite_client)
        appwrite_databases = Databases(appwrite_client)
        appwrite_storage = Storage(appwrite_client)

    except Exception as e:
        print(f"Could not connect to Appwrite: {e}. Appwrite features will be disabled.")
        appwrite_client = None # Disable Appwrite if connection fails


UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Hugging Face API Key
HF_API_KEY = os.environ.get("HF_API_KEY")
if not HF_API_KEY:
    print("WARNING: HF_API_KEY environment variable not set. Hugging Face LLM features will be disabled.")


# --- Helper Functions ---
def generate_id():
    return str(uuid.uuid4())


def generate_otp():
    return str(random.randint(100000, 999999))


def send_otp_email(to_email, otp):
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    sender_email = os.environ.get("SMTP_USER", 'your_email@gmail.com')
    sender_pass = os.environ.get("SMTP_PASS", 'your_app_password')

    if not sender_email or not sender_pass:
        print("SMTP_USER or SMTP_PASS environment variables not set. Email sending skipped.")
        return

    # Create message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "🔐 Your OTP for Resume Screening Verification"
    msg["From"] = sender_email
    msg["To"] = to_email

    # Plain text fallback
    text = f"""\
Hi,

Your OTP for Resume Screening verification is: {otp}

This OTP is valid for 10 minutes. Do not share it with anyone.

If you did not request this, please ignore this email.

Thanks,
Resume Screening Team
"""

    # HTML version
    html = f"""\
<html>
  <body style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">
    <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 8px; padding: 30px; box-shadow: 0px 0px 10px rgba(0,0,0,0.1);">
      <h2 style="color: #2e86de;">🔐 Resume Screening OTP Verification</h2>
      <p>Hi there,</p>
      <p>Your One-Time Password (OTP) for verifying your email address is:</p>
      <h1 style="color: #27ae60; letter-spacing: 4px;">{otp}</h1>
      <p>This OTP is valid for <strong>10 minutes</strong>. Please do not share it with anyone.</p>
      <hr style="margin: 30px 0;">
      <p style="font-size: 0.9em; color: #888888;">
        If you did not request this email, you can safely ignore it.<br>
        Need help? Contact us at <a href="mailto:nitin.renusharmafoundation@gmail.com">nitin.renusharmafoundation@gmail.com</a>
      </p>
      <p style="font-size: 0.9em; color: #888888;">Thanks,<br>The Resume Screening Team</p>
    </div>
  </body>
</html>
"""

    # Attach plain and HTML parts
    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")
    msg.attach(part1)
    msg.attach(part2)

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, sender_pass)
            server.send_message(msg)
        print(f"✅ OTP sent to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send OTP email to {to_email}: {e}")


# --- API Endpoints ---

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    email = data.get('email')
    phone = data.get('phone')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    if not appwrite_client:
        return jsonify({"message": "Database not connected. Signup is unavailable."}), 500

    try:
        response = appwrite_databases.list_documents(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_USERS_ID,
            queries=[Query.equal('email', email)]
        )
        existing_user_doc = response['documents'][0] if response['documents'] else None

        if existing_user_doc:
            if existing_user_doc.get('is_verified'):
                return jsonify({"message": "User with this email already exists and is verified"}), 409
            else:
                # User exists but not verified, resend OTP
                otp = generate_otp()
                # Update OTP in Appwrite database document
                appwrite_databases.update_document(
                    database_id=APPWRITE_DATABASE_ID,
                    collection_id=APPWRITE_COLLECTION_USERS_ID,
                    document_id=existing_user_doc['$id'],
                    data={'otp': otp}
                )
                send_otp_email(email, otp)
                return jsonify(
                    {"message": "User exists but not verified. OTP resent for email verification.", "user_id": existing_user_doc['$id']}), 200

        hashed_password = generate_password_hash(password)
        otp = generate_otp()

        appwrite_user_account = appwrite_users.create(
            user_id=generate_id(),
            email=email,
            password=password,
            phone=phone
        )

        insert_data = {
            'email': email,
            'phone': phone,
            'password_hash': hashed_password, # Store hashed password for verification later
            'otp': otp,
            'is_verified': False,
            'appwrite_account_id': appwrite_user_account['$id'] # Link to Appwrite Auth user ID
        }

        new_user_doc = appwrite_databases.create_document(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_USERS_ID,
            document_id=generate_id(), # Document ID for the profile data
            data=insert_data
        )

        if new_user_doc:
            user_id = new_user_doc['$id']
            print(f"User {email} registered with ID {user_id} in Appwrite.")
            send_otp_email(email, otp)
            return jsonify({"message": "User registered successfully. OTP sent for email verification.", "user_id": user_id}), 201
        else:
            return jsonify({"message": "Failed to register user."}), 500

    except AppwriteException as e:
        print(f"Appwrite signup error: {e.message}")
        if "A user with the same email already exists" in e.message:
            return jsonify({"message": "User with this email already exists."}), 409
        return jsonify({"message": f"An Appwrite error occurred during signup: {e.message}"}), 500
    except Exception as e:
        import traceback
        print(f"General signup error: {e}")
        traceback.print_exc()
        return jsonify({"message": f"An error occurred during signup: {str(e)}"}), 500


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    if not appwrite_client:
        return jsonify({"message": "Database not connected. Login is unavailable."}), 500

    try:
        # Fetch user document from Appwrite database
        response = appwrite_databases.list_documents(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_USERS_ID,
            queries=[Query.equal('email', email)]
        )
        user_doc = response['documents'][0] if response['documents'] else None

        if not user_doc or not check_password_hash(user_doc['password_hash'], password):
            return jsonify({"message": "Invalid email or password"}), 401

        if not user_doc.get('is_verified'):
            return jsonify({"message": "Please verify your email via OTP first."}), 403

        # Clear OTP from Appwrite after successful login
        appwrite_databases.update_document(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_USERS_ID,
            document_id=user_doc['$id'],
            data={'otp': None}
        )

        role_set = user_doc.get('role') is not None
        return jsonify({
            "message": "Login successful",
            "user_id": user_doc['$id'],
            "role_set": role_set,
            "email": user_doc['email'],
            "name": user_doc.get('full_name', user_doc['email'].split('@')[0]),
            "hr_id": user_doc.get('hr_id'),
            "role": user_doc.get('role'),
            "department": user_doc.get('department'),
            "position": user_doc.get('position')
        }), 200

    except AppwriteException as e:
        print(f"Appwrite login error: {e.message}")
        return jsonify({"message": f"An Appwrite error occurred during login: {e.message}"}), 500
    except Exception as e:
        print(f"General login error: {e}")
        return jsonify({"message": f"An error occurred during login: {str(e)}"}), 500


@app.route('/api/verify_otp', methods=['POST'])
def verify_otp():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')
    action = data.get('action', 'signup')

    if not appwrite_client:
        return jsonify({"message": "Database not connected. OTP verification is unavailable."}), 500

    try:
        response = appwrite_databases.list_documents(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_USERS_ID,
            queries=[Query.equal('email', email)]
        )
        user_doc = response['documents'][0] if response['documents'] else None

        if not user_doc or user_doc['otp'] != otp:
            return jsonify({"message": "Invalid OTP"}), 401

        # Clear OTP and update verification status in Appwrite
        update_data = {'otp': None}
        if action == 'signup':
            update_data['is_verified'] = True
            # Also update the Appwrite Auth user's email verification status
            if user_doc.get('appwrite_account_id'):
                appwrite_users.update_email_verification(user_doc['appwrite_account_id'], True)


        appwrite_databases.update_document(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_USERS_ID,
            document_id=user_doc['$id'],
            data=update_data
        )

        if action == 'signup':
            role_set = user_doc.get('role') is not None
            return jsonify({
                "message": "Email verified and login successful",
                "user_id": user_doc['$id'],
                "role_set": role_set,
                "email": email,
                "name": user_doc.get('full_name', email.split('@')[0]),
                "hr_id": user_doc.get('hr_id'),
                "role": user_doc.get('role'),
                "department": user_doc.get('department'),
                "position": user_doc.get('position')
            }), 200
        elif action == 'reset_password':
            return jsonify({"message": "OTP verified. You can now reset your password.", "user_id": user_doc['$id']}), 200
        else:
            return jsonify({"message": "Invalid action for OTP verification"}), 400

    except AppwriteException as e:
        print(f"Appwrite OTP verification error: {e.message}")
        return jsonify({"message": f"An Appwrite error occurred during OTP verification: {e.message}"}), 500
    except Exception as e:
        print(f"General OTP verification error: {e}")
        return jsonify({"message": f"An error occurred during OTP verification: {str(e)}"}), 500


@app.route('/api/forgot_password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    if not appwrite_client:
        return jsonify({"message": "Database not connected. Forgot password is unavailable."}), 500

    try:
        response = appwrite_databases.list_documents(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_USERS_ID,
            queries=[Query.equal('email', email)]
        )
        user_doc = response['documents'][0] if response['documents'] else None

        if not user_doc:
            return jsonify({"message": "User not found"}), 404

        otp = generate_otp()
        # Store OTP in Appwrite for the user
        appwrite_databases.update_document(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_USERS_ID,
            document_id=user_doc['$id'],
            data={'otp': otp}
        )

        send_otp_email(email, otp)
        print(f"Demo OTP for password reset for {email}: {otp}")
        return jsonify({"message": "OTP sent to your email for password reset"}), 200

    except AppwriteException as e:
        print(f"Appwrite forgot password error: {e.message}")
        return jsonify({"message": f"An Appwrite error occurred during forgot password: {e.message}"}), 500
    except Exception as e:
        print(f"General forgot password error: {e}")
        return jsonify({"message": f"An error occurred during forgot password: {str(e)}"}), 500


@app.route('/api/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    new_password = data.get('new_password')

    if not appwrite_client:
        return jsonify({"message": "Database not connected. Password reset is unavailable."}), 500

    try:
        response = appwrite_databases.list_documents(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_USERS_ID,
            queries=[Query.equal('email', email)]
        )
        user_doc = response['documents'][0] if response['documents'] else None

        if not user_doc:
            return jsonify({"message": "User not found"}), 404

        hashed_new_password = generate_password_hash(new_password)
        # Update password_hash in Appwrite
        appwrite_databases.update_document(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_USERS_ID,
            document_id=user_doc['$id'],
            data={'password_hash': hashed_new_password, 'otp': None}
        )
        # Also update the password in Appwrite Auth if linked
        if user_doc.get('appwrite_account_id'):
            appwrite_users.update_password(user_doc['appwrite_account_id'], new_password)


        return jsonify({"message": "Password reset successfully"}), 200

    except AppwriteException as e:
        print(f"Appwrite reset password error: {e.message}")
        return jsonify({"message": f"An Appwrite error occurred during password reset: {e.message}"}), 500
    except Exception as e:
        print(f"General reset password error: {e}")
        return jsonify({"message": f"An error occurred during password reset: {str(e)}"}), 500


@app.route('/api/select_role', methods=['POST', 'PUT'])
def select_role():
    data = request.json
    email = data.get('email')
    role = data.get('role')
    full_name = data.get('full_name')
    hr_id = data.get('hr_id')
    position = data.get('position')
    department = data.get('department')

    if not email:
        return jsonify({"message": "User ID is required"}), 400

    if not appwrite_client:
        return jsonify({"message": "Database not connected. Role selection is unavailable."}), 500

    try:
        response = appwrite_databases.list_documents(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_USERS_ID,
            queries=[Query.equal('email', email)]
        )
        user_doc = response['documents'][0] if response['documents'] else None

        if not user_doc:
            return jsonify({"message": "User not found"}), 404

        # Update user's details in Appwrite 'users' collection
        update_data = {
            'role': role,
            'hr_id': hr_id,
            'full_name': full_name,
            'position': position,
            'department': department
        }
        updated_doc = appwrite_databases.update_document(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_USERS_ID,
            document_id=user_doc['$id'],
            data=update_data
        )

        if updated_doc:
            return jsonify({"message": f"Role '{role}' and HR info updated for {email}"}), 200
        else:
            return jsonify({"message": "User not found or failed to update"}), 404

    except AppwriteException as e:
        print(f"Appwrite select role error: {e.message}")
        return jsonify({"message": f"An Appwrite error occurred during role selection: {e.message}"}), 500
    except Exception as e:
        print(f"General select role error: {e}")
        return jsonify({"message": f"An error occurred during role selection: {str(e)}"}), 500


@app.route('/api/job_requirements', methods=['POST'])
def save_job_requirements():
    data = request.json
    user_id = data.get('user_id')
    job_description = data.get('job_description')
    department = data.get('department')
    skills = data.get('skills')
    experience_required = data.get('experience_required')

    if not user_id or not job_description or not skills:
        return jsonify({"message": "User ID, job description, and skills are required"}), 400

    if not appwrite_client:
        return jsonify({"message": "Database not connected. Job requirements saving is unavailable."}), 500

    try:
        job_id = generate_id()
        insert_data = {
            'user_id': user_id,
            'job_description': job_description,
            'department': department,
            'skills': skills,
            'experience_required': experience_required
        }
        new_job_req_doc = appwrite_databases.create_document(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_JOB_REQUIREMENTS_ID,
            document_id=job_id, # Use generated ID as document ID
            data=insert_data
        )
        print(f"Job requirements saved in Appwrite with ID: {job_id}")
        return jsonify({"message": "Job requirements saved", "job_id": job_id}), 201

    except AppwriteException as e:
        print(f"Appwrite save job requirements error: {e.message}")
        return jsonify({"message": f"An Appwrite error occurred: {e.message}"}), 500
    except Exception as e:
        print(f"General save job requirements error: {e}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500


@app.route('/api/upload_resumes', methods=['POST'])
def upload_resumes():
    if 'files' not in request.files:
        return jsonify({"message": "No file part"}), 400

    files = request.files.getlist('files')
    uploaded_resume_ids = []

    if not appwrite_client:
        return jsonify({"message": "Database or Storage not connected. Resume upload is unavailable."}), 500

    for file in files:
        if file.filename == '':
            continue

        original_filename = file.filename
        file_extension = os.path.splitext(original_filename)[1]
        appwrite_file_id = str(uuid.uuid4())
        unique_local_filename = f"{appwrite_file_id}{file_extension}"
        filepath_local = os.path.join(app.config['UPLOAD_FOLDER'], unique_local_filename)

        file.save(filepath_local)

        try:
            input_file = InputFile.from_path(filepath_local)

            appwrite_file = appwrite_storage.create_file(
                bucket_id=APPWRITE_BUCKET_RESUMES_ID,
                file_id=appwrite_file_id,
                file=input_file
            )

            file_storage_id = appwrite_file['$id']
            file_storage_path = f"{APPWRITE_ENDPOINT}/storage/buckets/{APPWRITE_BUCKET_RESUMES_ID}/files/{file_storage_id}/view?project={APPWRITE_PROJECT_ID}"

            raw_text = extract_text_from_file(filepath_local)
            processed_text = preprocess_text(raw_text)
            extracted_skills = extract_skills_from_text(processed_text)
            categorized_field = categorize_resume(processed_text)

            resume_id = generate_id()
            insert_data = {
                'filename': original_filename,
                'filepath': file_storage_path,
                'appwrite_file_id': file_storage_id,
                'raw_text': raw_text,
                'processed_text': processed_text,
                'extracted_skills': extracted_skills,
                'categorized_field': categorized_field
            }
            new_resume_doc = appwrite_databases.create_document(
                database_id=APPWRITE_DATABASE_ID,
                collection_id=APPWRITE_COLLECTION_RESUMES_ID,
                document_id=resume_id,
                data=insert_data
            )
            uploaded_resume_ids.append(resume_id)

        except AppwriteException as e:
            print(f"Appwrite upload resume error for {original_filename}: {e.message}")
            if os.path.exists(filepath_local):
                os.remove(filepath_local)
            return jsonify({"message": f"Failed to upload {original_filename}: {e.message}"}), 500
        except Exception as e:
            print(f"General upload resume error for {original_filename}: {e}")
            if os.path.exists(filepath_local):
                os.remove(filepath_local)
            return jsonify({"message": f"An error occurred processing {original_filename}: {str(e)}"}), 500
        finally:
            if os.path.exists(filepath_local):
                os.remove(filepath_local)

    return jsonify({"message": "Resumes uploaded and processed", "resume_ids": uploaded_resume_ids}), 200

@app.route('/api/screen_resumes', methods=['POST'])
def screen_resumes():
    data = request.json
    job_id = data.get('job_id')
    resume_ids = data.get('resume_ids')

    if not appwrite_client:
        return jsonify({"message": "Database not connected. Screening is unavailable."}), 500

    try:
        # Fetch job requirements from Appwrite
        job_req_doc = appwrite_databases.get_document(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_JOB_REQUIREMENTS_ID,
            document_id=job_id
        )

        if not job_req_doc:
            return jsonify({"message": "Job requirements not found or session expired. Please re-enter job details."}), 404

        job_description_text = job_req_doc['job_description']
        required_skills = job_req_doc['skills']
        required_department = job_req_doc['department']
        experience_required = job_req_doc['experience_required']

        results = []
        # REMOVED: Redundant in-memory cache logic
        # screening_results_db.clear()

        for resume_id in resume_ids:
            try:
                resume_data_doc = appwrite_databases.get_document(
                    database_id=APPWRITE_DATABASE_ID,
                    collection_id=APPWRITE_COLLECTION_RESUMES_ID,
                    document_id=resume_id
                )
            except AppwriteException as e:
                print(f"Resume ID {resume_id} not found in Appwrite: {e.message}. Skipping.")
                continue

            resume_processed_text = resume_data_doc['processed_text']
            resume_extracted_skills = resume_data_doc['extracted_skills']
            resume_categorized_field = resume_data_doc['categorized_field']

            # Call the enhanced match score function
            match_score, matched_skills = calculate_match_score_enhanced(
                job_description_text,
                required_skills,
                experience_required,
                resume_processed_text,
                resume_extracted_skills,
                HF_API_KEY
            )

            department_match_factor = 1.0
            if required_department and required_department.lower() in resume_processed_text.lower():
                department_match_factor = 1.05

            final_score = int(match_score * department_match_factor)
            final_score = min(final_score, 100)

            # Store screening result in Appwrite
            screening_result_doc_id = generate_id()
            screening_result_data = {
                'job_id': job_id,
                'resume_id': resume_id,
                'filename': resume_data_doc['filename'],
                'filepath': resume_data_doc['filepath'],
                'appwrite_file_id': resume_data_doc['appwrite_file_id'],
                'raw_text': resume_data_doc['raw_text'],
                'match_score': final_score,
                'matched_skills': matched_skills,
                'department': required_department,
                'categorized_field': resume_categorized_field
            }
            new_screening_result_doc = appwrite_databases.create_document(
                database_id=APPWRITE_DATABASE_ID,
                collection_id=APPWRITE_COLLECTION_SCREENING_RESULTS_ID,
                document_id=screening_result_doc_id,
                data=screening_result_data
            )
            # REMOVED: Redundant in-memory cache logic
            # screening_results_db[resume_id] = new_screening_result_doc
            results.append(new_screening_result_doc)

        return jsonify({"message": "Screening complete", "results": results}), 200

    except AppwriteException as e:
        print(f"Appwrite screen resumes error: {e.message}")
        return jsonify({"message": f"An Appwrite error occurred during screening: {e.message}"}), 500
    except Exception as e:
        print(f"General screen resumes error: {e}")
        return jsonify({"message": f"An error occurred during screening: {str(e)}"}), 500


# MODIFIED: This endpoint now fetches directly from Appwrite
@app.route('/api/dashboard_data', methods=['GET'])
def get_dashboard_data():
    job_id = request.args.get('job_id')
    if not job_id:
        return jsonify({"message": "A job_id is required to fetch dashboard data."}), 400

    if not appwrite_client:
        return jsonify({"message": "Database not connected."}), 500

    try:
        # NEW: Fetch results directly from Appwrite for the specific job
        response = appwrite_databases.list_documents(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_SCREENING_RESULTS_ID,
            queries=[Query.equal('job_id', job_id)]
        )
        results = response['documents']

        sort_by = request.args.get('sort_by', 'score')
        if sort_by == 'score':
            results.sort(key=lambda x: x['match_score'], reverse=True)
        elif sort_by == 'name':
            results.sort(key=lambda x: x['filename'])

        formatted_results = []
        for res in results:
            formatted_results.append({
                'id': res['resume_id'],
                'name': res['filename'].split('.')[0],
                'matchScore': res['match_score'],
                'matchedSkills': res['matched_skills'],
                'department': res.get('department', 'N/A'),
                'category': res.get('categorized_field', 'Uncategorized'),
                'shortlisted': False
            })

        return jsonify(formatted_results), 200

    except AppwriteException as e:
        print(f"Appwrite dashboard data error: {e.message}")
        return jsonify({"message": f"An Appwrite error occurred: {e.message}"}), 500
    except Exception as e:
        print(f"General dashboard data error: {e}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500


@app.route('/api/resume/<resume_id>', methods=['GET'])
def get_resume_raw_text(resume_id):
    if not appwrite_client:
        return jsonify({"message": "Database not connected."}), 500
    try:
        resume_doc = appwrite_databases.get_document(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_RESUMES_ID,
            document_id=resume_id
        )
        return jsonify({"content": resume_doc['raw_text']}), 200
    except AppwriteException as e:
        print(f"Appwrite get resume raw text error: {e.message}")
        return jsonify({"message": "Resume not found"}), 404
    except Exception as e:
        print(f"General get resume raw text error: {e}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500


@app.route('/api/download_all_resumes/<job_id>', methods=['GET'])
def download_all_resumes_for_job(job_id):
    if not appwrite_client:
        return jsonify({"message": "Database or Storage not connected."}), 500

    resumes_to_download = []
    try:
        # Fetch all screening results for the given job_id
        response = appwrite_databases.list_documents(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_SCREENING_RESULTS_ID,
            queries=[Query.equal('job_id', job_id)]
        )
        resumes_to_download = response['documents']

    except AppwriteException as e:
        print(f"Appwrite download all resumes error: {e.message}")
        return jsonify({"message": f"Error fetching resumes: {e.message}"}), 500

    if not resumes_to_download:
        return jsonify({"message": "No resumes found for this job ID."}), 404

    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for resume_data in resumes_to_download:
            original_filename = resume_data.get('filename')
            appwrite_file_id = resume_data.get('appwrite_file_id')

            if appwrite_file_id and original_filename:
                try:
                    # Download file from Appwrite Storage
                    file_bytes = appwrite_storage.get_file_download(
                        bucket_id=APPWRITE_BUCKET_RESUMES_ID,
                        file_id=appwrite_file_id
                    )
                    zf.writestr(original_filename, file_bytes)
                except AppwriteException as e:
                    print(f"Failed to download file {appwrite_file_id} from Appwrite: {e.message}")
                except Exception as e:
                    print(f"General error downloading file {appwrite_file_id}: {e}")

    memory_file.seek(0)
    response = make_response(memory_file.getvalue())
    response.headers['Content-Type'] = 'application/zip'
    response.headers['Content-Disposition'] = f'attachment; filename=all_resumes_{job_id}.zip'
    return response

@app.route('/api/download_resume', methods=['POST'])
def download_resume_file():
    data = request.json
    resume_id = data.get('resume_id')

    if not resume_id:
        return jsonify({"message": "Resume ID is required"}), 400

    if not appwrite_client:
        return jsonify({"message": "Storage not connected."}), 500

    try:
        resume_doc = appwrite_databases.get_document(
            database_id=APPWRITE_DATABASE_ID,
            collection_id=APPWRITE_COLLECTION_RESUMES_ID,
            document_id=resume_id
        )
        appwrite_file_id = resume_doc.get('appwrite_file_id')
        original_filename = resume_doc.get('filename')

        if not appwrite_file_id or not original_filename:
            return jsonify({"message": "File information not found for this resume."}), 404

        file_bytes = appwrite_storage.get_file_download(
            bucket_id=APPWRITE_BUCKET_RESUMES_ID,
            file_id=appwrite_file_id
        )

        mimetype, _ = guess_type(original_filename)
        response = make_response(file_bytes)
        response.headers['Content-Type'] = mimetype or 'application/octet-stream'
        response.headers['Content-Disposition'] = f'attachment; filename="{original_filename}"'
        return response

    except AppwriteException as e:
        print(f"Appwrite download resume file error: {e.message}")
        return jsonify({"message": "File not found or access denied."}), 404
    except Exception as e:
        print(f"General download resume file error: {e}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500


@app.route('/api/download_all_filtered_resumes', methods=['POST'])
def download_all_filtered_resumes():
    data = request.json
    filtered_resume_ids = data.get('filtered_resume_ids', [])

    if not filtered_resume_ids:
        return jsonify({"message": "No filtered resumes to download."}), 404

    if not appwrite_client:
        return jsonify({"message": "Database or Storage not connected."}), 500

    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for resume_id in filtered_resume_ids:
            try:
                resume_doc = appwrite_databases.get_document(
                    database_id=APPWRITE_DATABASE_ID,
                    collection_id=APPWRITE_COLLECTION_RESUMES_ID,
                    document_id=resume_id
                )
                appwrite_file_id = resume_doc.get('appwrite_file_id')
                original_filename = resume_doc.get('filename')

                if appwrite_file_id and original_filename:
                    file_bytes = appwrite_storage.get_file_download(
                        bucket_id=APPWRITE_BUCKET_RESUMES_ID,
                        file_id=appwrite_file_id
                    )
                    zf.writestr(original_filename, file_bytes)
                else:
                    print(f"Missing file ID or filename for resume_id {resume_id}")
            except AppwriteException as e:
                print(f"Failed to fetch or download resume {resume_id} from Appwrite: {e.message}")
            except Exception as e:
                print(f"General error processing filtered resume {resume_id}: {e}")

    memory_file.seek(0)
    response = make_response(memory_file.getvalue())
    response.headers['Content-Type'] = 'application/zip'
    response.headers['Content-Disposition'] = 'attachment; filename=filtered_resumes.zip'
    return response

@app.route('/success')
def email_verified_success():
    return '✅ Email verified successfully. You can now return to your app and login.'

@app.route('/<path:path>')
def catch_all(path):
    return 'Page not found', 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)