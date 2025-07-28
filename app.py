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
from supabase import create_client, Client # Import Supabase client
from mimetypes import guess_type

# Load environment variables from .env file
load_dotenv()

# Import your NLP processing modules (assuming these exist)
# Ensure these modules are available in your Render environment
from text_extractor import extract_text_from_file
from text_processor import preprocess_text, \
    extract_skills_from_text, categorize_resume
from resume_matcher import calculate_match_score_enhanced


app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

# --- Database (Supabase Integration) ---
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    # For local development, you might want to print a warning instead of raising an error
    # raise ValueError("SUPABASE_URL and SUPABASE_KEY environment variables must be set.")
    print("WARNING: SUPABASE_URL and SUPABASE_KEY environment variables are not set. Supabase features will not work.")
    # Set dummy values for local testing if you don't have Supabase set up
    SUPABASE_URL = "http://localhost:8000"
    SUPABASE_KEY = "dummy_key"

try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
except Exception as e:
    print(f"Could not connect to Supabase: {e}. Supabase features will be disabled.")
    supabase = None # Disable Supabase if connection fails


# In-memory dbs for temporary session data
resumes_db = {}  # Stores processed resume data and original file path
screening_results_db = {}  # Stores results of the *last* screening operation
job_requirements_db = {} # Stores job requirements temporarily for the current session

# --- Configuration ---
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

    if not supabase:
        return jsonify({"message": "Database not connected. Signup is unavailable."}), 500

    try:
        # Check if user already exists in Supabase 'users' table
        response = supabase.table('users').select('id', 'is_verified').eq('email', email).execute()
        existing_user = response.data[0] if response.data else None

        if existing_user:
            if existing_user.get('is_verified'):
                return jsonify({"message": "User with this email already exists and is verified"}), 409
            else:
                # User exists but not verified, resend OTP
                otp = generate_otp()
                # Update OTP in Supabase
                supabase.table('users').update({'otp': otp}).eq('email', email).execute()
                send_otp_email(email, otp)
                return jsonify(
                    {"message": "User exists but not verified. OTP resent for email verification.", "user_id": existing_user['id']}), 200

        hashed_password = generate_password_hash(password)
        otp = generate_otp()

        # Insert new user into Supabase 'users' table
        insert_data = {
            'email': email,
            'phone': phone,
            'password_hash': hashed_password,
            'otp': otp,
            'is_verified': False
        }

        response = supabase.table('users').insert(insert_data).execute()

        if response.data:
            user_id = response.data[0]['id']
            print(f"User {email} registered with ID {user_id} in Supabase.")
            send_otp_email(email, otp)
            return jsonify({"message": "User registered successfully. OTP sent for email verification.", "user_id": user_id}), 201
        else:
            return jsonify({"message": "Failed to register user."}), 500

    except Exception as e:
        import traceback
        print(f"Supabase signup error: {e}")
        traceback.print_exc()
        return jsonify({"message": f"An error occurred during signup: {str(e)}"}), 500


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    if not supabase:
        return jsonify({"message": "Database not connected. Login is unavailable."}), 500

    try:
        response = supabase.table('users').select('*').eq('email', email).execute()
        user = response.data[0] if response.data else None

        if not user or not check_password_hash(user['password_hash'], password):
            return jsonify({"message": "Invalid email or password"}), 401

        if not user.get('is_verified'):
            return jsonify({"message": "Please verify your email via OTP first."}), 403

        # Clear OTP from Supabase after successful login (if it was still there)
        supabase.table('users').update({'otp': None}).eq('email', email).execute()

        role_set = user.get('role') is not None
        return jsonify({
            "message": "Login successful",
            "user_id": user['id'],
            "role_set": role_set,
            "email": user['email'],
            "name": user.get('full_name', user['email'].split('@')[0]), # Pass full_name if available
            "hr_id": user.get('hr_id'),
            "role": user.get('role'),
            "department": user.get('department'),
            "position": user.get('position')
        }), 200

    except Exception as e:
        print(f"Supabase login error: {e}")
        return jsonify({"message": f"An error occurred during login: {str(e)}"}), 500


@app.route('/api/verify_otp', methods=['POST'])
def verify_otp():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')
    action = data.get('action', 'signup')

    if not supabase:
        return jsonify({"message": "Database not connected. OTP verification is unavailable."}), 500

    try:
        response = supabase.table('users').select('id', 'otp', 'is_verified', 'role', 'full_name', 'hr_id', 'department', 'position').eq('email', email).execute()
        user = response.data[0] if response.data else None

        if not user or user['otp'] != otp:
            return jsonify({"message": "Invalid OTP"}), 401

        # Clear OTP and update verification status in Supabase
        update_data = {'otp': None}
        if action == 'signup':
            update_data['is_verified'] = True

        supabase.table('users').update(update_data).eq('email', email).execute()

        if action == 'signup':
            role_set = user.get('role') is not None
            return jsonify({
                "message": "Email verified and login successful",
                "user_id": user['id'],
                "role_set": role_set,
                "email": email,
                "name": user.get('full_name', email.split('@')[0]),
                "hr_id": user.get('hr_id'),
                "role": user.get('role'),
                "department": user.get('department'),
                "position": user.get('position')
            }), 200
        elif action == 'reset_password':
            return jsonify({"message": "OTP verified. You can now reset your password.", "user_id": user['id']}), 200
        else:
            return jsonify({"message": "Invalid action for OTP verification"}), 400

    except Exception as e:
        print(f"Supabase OTP verification error: {e}")
        return jsonify({"message": f"An error occurred during OTP verification: {str(e)}"}), 500


@app.route('/api/forgot_password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    if not supabase:
        return jsonify({"message": "Database not connected. Forgot password is unavailable."}), 500

    try:
        response = supabase.table('users').select('id').eq('email', email).execute()
        user = response.data[0] if response.data else None

        if not user:
            return jsonify({"message": "User not found"}), 404

        otp = generate_otp()
        # Store OTP in Supabase for the user
        supabase.table('users').update({'otp': otp}).eq('email', email).execute()

        send_otp_email(email, otp)
        print(f"Demo OTP for password reset for {email}: {otp}")
        return jsonify({"message": "OTP sent to your email for password reset"}), 200

    except Exception as e:
        print(f"Supabase forgot password error: {e}")
        return jsonify({"message": f"An error occurred during forgot password: {str(e)}"}), 500


@app.route('/api/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    new_password = data.get('new_password')

    if not supabase:
        return jsonify({"message": "Database not connected. Password reset is unavailable."}), 500

    try:
        response = supabase.table('users').select('id').eq('email', email).execute()
        user = response.data[0] if response.data else None

        if not user:
            return jsonify({"message": "User not found"}), 404

        hashed_new_password = generate_password_hash(new_password)
        # Update password_hash in Supabase
        supabase.table('users').update({'password_hash': hashed_new_password, 'otp': None}).eq('email', email).execute()

        return jsonify({"message": "Password reset successfully"}), 200

    except Exception as e:
        print(f"Supabase reset password error: {e}")
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

    if not supabase:
        return jsonify({"message": "Database not connected. Role selection is unavailable."}), 500

    try:
        # Update user's details in Supabase 'users' table
        update_data = {
            'role': role,
            'hr_id': hr_id,
            'full_name': full_name,
            'position': position,
            'department': department
        }
        response = supabase.table('users').update(update_data).eq('email', email).execute()

        if response.data:
            return jsonify({"message": f"Role '{role}' and HR info updated for {email}"}), 200
        else:
            return jsonify({"message": "User not found or failed to update"}), 404

    except Exception as e:
        print(f"Supabase select role error: {e}")
        return jsonify({"message": f"An error occurred during role selection: {str(e)}"}), 500


@app.route('/api/job_requirements', methods=['POST'])
def save_job_requirements():
    data = request.json
    user_id = data.get('user_id')
    job_description = data.get('job_description')
    department = data.get('department')
    skills = data.get('skills')
    experience_required = data.get('experience_required') # New field

    if not user_id or not job_description or not skills:
        return jsonify({"message": "User ID, job description, and skills are required"}), 400

    # Generate a unique ID for this set of job requirements
    job_id = generate_id()

    # Store job requirements in-memory for temporary use
    job_requirements_db[job_id] = {
        'user_id': user_id,
        'job_description': job_description,
        'department': department,
        'skills': skills,
        'experience_required': experience_required # Store new field
    }
    print(f"Job requirements saved in-memory with ID: {job_id}")
    return jsonify({"message": "Job requirements saved temporarily", "job_id": job_id}), 201


@app.route('/api/upload_resumes', methods=['POST'])
def upload_resumes():
    if 'files' not in request.files:
        return jsonify({"message": "No file part"}), 400

    files = request.files.getlist('files')
    uploaded_resume_ids = []

    for file in files:
        if file.filename == '':
            continue

        original_filename = file.filename
        unique_filename = f"{uuid.uuid4()}_{original_filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)

        raw_text = extract_text_from_file(filepath)
        processed_text = preprocess_text(raw_text)
        extracted_skills = extract_skills_from_text(processed_text)
        categorized_field = categorize_resume(processed_text) # New categorization

        resume_id = generate_id()
        resumes_db[resume_id] = {
            'filename': original_filename,
            'filepath': unique_filename,
            'raw_text': raw_text,
            'processed_text': processed_text,
            'extracted_skills': extracted_skills,
            'categorized_field': categorized_field # Store new field
        }
        uploaded_resume_ids.append(resume_id)

    return jsonify({"message": "Resumes uploaded and processed", "resume_ids": uploaded_resume_ids}), 200


@app.route('/api/screen_resumes', methods=['POST'])
def screen_resumes():
    data = request.json
    job_id = data.get('job_id')
    resume_ids = data.get('resume_ids')

    # --- DEBUGGING STEP 1 ---
    #print(f"--- Screening Resumes for Job ID: {job_id} ---")
    #print(f"Received Resume IDs: {resume_ids}")
    #print(f"Current Resumes in DB: {list(resumes_db.keys())}")
    # -------------------------

    # Fetch job requirements from in-memory storage
    job_req = job_requirements_db.get(job_id)

    if not job_req:
        return jsonify({"message": "Job requirements not found or session expired. Please re-enter job details."}), 404

    job_description_text = job_req['job_description']
    required_skills = job_req['skills']
    required_department = job_req['department']
    experience_required = job_req['experience_required'] # New field

    results = []
    screening_results_db.clear() # Clear previous screening results

    for resume_id in resume_ids:
        if resume_id not in resumes_db:
            # --- DEBUGGING STEP 2 ---
            #print(f"WARNING: Resume ID {resume_id} not found in resumes_db. Skipping.")
            # -------------------------
            continue

        resume_data = resumes_db[resume_id]
        resume_processed_text = resume_data['processed_text']
        resume_extracted_skills = resume_data['extracted_skills']
        resume_categorized_field = resume_data['categorized_field'] # New field
        # --- DEBUGGING STEP 3 ---
        #print(f"Processing Resume: {resume_data.get('filename')}")
        # -------------------------

        # Call the enhanced match score function
        match_score, matched_skills = calculate_match_score_enhanced(
            job_description_text,
            required_skills,
            experience_required, # Pass new field
            resume_processed_text,
            resume_extracted_skills,
            HF_API_KEY # Pass Hugging Face API Key
        )

        department_match_factor = 1.0
        # Check if required_department is present in the resume's processed text
        if required_department and required_department.lower() in resume_processed_text.lower():
            department_match_factor = 1.05 # Apply a small boost for department match

        final_score = int(match_score * department_match_factor)
        final_score = min(final_score, 100) # Cap score at 100
        # --- DEBUGGING STEP 4 ---
        #print(f"Calculated Score for {resume_data.get('filename')}: {final_score}")
        # -------------------------
        screening_results_db[resume_id] = {
            'job_id': job_id,
            'resume_id': resume_id,
            'filename': resume_data['filename'],
            'filepath': resume_data['filepath'],
            'raw_text': resume_data['raw_text'],  # Include raw text for view
            'match_score': final_score,
            'matched_skills': matched_skills,
            'department': required_department,  # Include department in results for display
            'categorized_field': resume_categorized_field  # Include categorized field
        }
        results.append(screening_results_db[resume_id])
        # --- DEBUGGING STEP 5 ---
        #print(f"--- Final Screening Results to be Sent: {results} ---")
        # -------------------------
    return jsonify({"message": "Screening complete", "results": results}), 200


@app.route('/api/dashboard_data', methods=['GET'])
def get_dashboard_data():
    results = list(screening_results_db.values())

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


@app.route('/api/resume/<resume_id>', methods=['GET'])
def get_resume_raw_text(resume_id):
    if resume_id in resumes_db:
        # IMPORTANT: The frontend expects a 'content' field, not 'raw_text'.
        return jsonify({"content": resumes_db[resume_id]['raw_text']}), 200
    return jsonify({"message": "Resume not found"}), 404

@app.route('/api/download_all_resumes/<job_id>', methods=['GET'])
def download_all_resumes_for_job(job_id):
    # This logic assumes you want to download all resumes associated with a screening,
    # not just the filtered ones.
    resumes_to_download = []
    for resume_id, result in screening_results_db.items():
        if result['job_id'] == job_id:
            resumes_to_download.append(result)

    if not resumes_to_download:
        return jsonify({"message": "No resumes found for this job ID."}), 404

    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for resume_data in resumes_to_download:
            unique_filename_on_server = resume_data.get('filepath')
            original_filename = resume_data.get('filename')

            if unique_filename_on_server and original_filename:
                full_filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename_on_server)
                if os.path.exists(full_filepath):
                    zf.write(full_filepath, arcname=original_filename)

    memory_file.seek(0)
    response = make_response(memory_file.getvalue())
    response.headers['Content-Type'] = 'application/zip'
    response.headers['Content-Disposition'] = f'attachment; filename=all_resumes_{job_id}.zip'
    return response

@app.route('/api/download_resume', methods=['POST'])
def download_resume_file():
    data = request.json
    unique_filename_on_server = data.get('filepath')

    # You can still get the original filename from resumes_db if it exists,
    # but it's better to get it from the frontend too for statelessness.
    # For now, let's just use the unique name if original is not available.
    original_filename = unique_filename_on_server.split('_', 1)[-1]  # A simple way to get original name

    if not unique_filename_on_server:
        return jsonify({"message": "Filepath is required"}), 400

    full_filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename_on_server)

    # Security check: Ensure the file is within the UPLOAD_FOLDER
    if os.path.exists(full_filepath) and os.path.abspath(os.path.dirname(full_filepath)) == os.path.abspath(
            app.config['UPLOAD_FOLDER']):
        mimetype, _ = guess_type(original_filename)
        return send_from_directory(app.config['UPLOAD_FOLDER'], unique_filename_on_server, as_attachment=True,download_name=original_filename, mimetype=mimetype or 'application/octet-stream')
    else:
        return jsonify({"message": "File not found on server or invalid path"}), 404

@app.route('/api/download_all_filtered_resumes', methods=['POST'])
def download_all_filtered_resumes():
    data = request.json
    filtered_resume_ids = data.get('filtered_resume_ids', [])

    if not filtered_resume_ids:
        return jsonify({"message": "No filtered resumes to download."}), 404

    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for resume_id in filtered_resume_ids:
            result = screening_results_db.get(resume_id)
            if result:
                unique_filename_on_server = result.get('filepath')
                original_filename = result.get('filename')

                if unique_filename_on_server and original_filename:
                    full_filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename_on_server)
                    if os.path.exists(full_filepath):
                        # Security check: Ensure the file is within the UPLOAD_FOLDER
                        if os.path.abspath(os.path.dirname(full_filepath)) == os.path.abspath(
                                app.config['UPLOAD_FOLDER']):
                            zf.write(full_filepath, arcname=original_filename)
                        else:
                            print(f"Skipping file outside UPLOAD_FOLDER: {full_filepath}")
                    else:
                        print(f"File not found for resume_id {resume_id}: {full_filepath}")
                else:
                    print(f"Missing filename or filepath for resume_id {resume_id}")
            else:
                print(f"Resume ID {resume_id} not found in screening results for download.")

    memory_file.seek(0)
    response = make_response(memory_file.getvalue())
    response.headers['Content-Type'] = 'application/zip'
    response.headers['Content-Disposition'] = 'attachment; filename=filtered_resumes.zip'
    return response

@app.route('/api/clear_session_data', methods=['POST'])
def clear_session_data():
    global resumes_db, screening_results_db, job_requirements_db
    resumes_db = {}
    screening_results_db = {}
    job_requirements_db = {}
    print("Backend session data cleared.")
    return jsonify({"message": "Session data cleared successfully"}), 200

# Catch-all route for email verification success (from previous context)
@app.route('/success')
def email_verified_success():
    return '✅ Email verified successfully. You can now return to your app and login.'

@app.route('/<path:path>')
def catch_all(path):
    # This route is a fallback and might catch requests for static files if not configured correctly
    # For Render, ensure static files are served by the web server (e.g., Nginx) or Flask's static handler
    return 'Page not found', 404


if __name__ == "__main__":
    # Use environment variable for PORT, default to 5000
    port = int(os.environ.get("PORT", 5000))
    # Bind to 0.0.0.0 for Render deployment
    app.run(debug=True, host='0.0.0.0', port=port)

