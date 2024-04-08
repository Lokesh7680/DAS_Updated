from fastapi import APIRouter, HTTPException, Body, Depends,Request,status
from typing import Dict
from uuid import uuid4
from pydantic import BaseModel
from app.services.email_service import send_email, send_password_reset_email,notify_watchers_about_document_creation
from app.services.otp_service import generate_otp, verify_otp
from app.utils.db_utils import get_next_sequence, update_password_in_database
from app.utils.auth_utils import get_current_user
from app.dependencies.auth_logic import verify_user_role
from pymongo import MongoClient
from app.utils.file_utils import save_document
from typing import List
import jwt
from app.utils.decorators import role_required
from app.config import Settings
from fastapi.security import OAuth2PasswordBearer
import string 
import random
import hashlib

# Define the OAuth2PasswordBearer for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


admin_router = APIRouter()
mongo_uri = "mongodb+srv://loki_user:loki_password@clmdemo.1yw93ku.mongodb.net/?retryWrites=true&w=majority&appName=Clmdemo"
client = MongoClient(mongo_uri)
db = client['CLMDigiSignDB']
temp_storage = {}  # Temporary storage for admin data during OTP process

# Define the secret key and algorithm for JWT tokens
SECRET_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
ALGORITHM = "HS256"
settings = Settings()

# Include this function to validate JWT tokens in incoming requests
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
        
        # Replace the following with your custom logic to retrieve user information from the token
        user = db.users.find_one({"email": email})
        print(user)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")

        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
temp_storage: Dict[str, dict] = {}

def generate_password(admin_email, length=8):
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

from datetime import datetime, timedelta

temp_storage = {}

@admin_router.post('/create_admin')
async def create_admin(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    
    company_email = data.get('company_email')
    company_name = data.get('company_name')
    industry = data.get('industry')
    country = data.get('country')
    state = data.get('state')
    city = data.get('city')
    pincode = data.get('pincode')
    language = data.get('language')
    website = data.get('website')
    timezone = data.get('timezone')
    num_employees = data.get('num_employees')
    company_phone_number = data.get('company_phone_number')

    # Generate a random password for the admin
    password = generate_password(company_email)

    # Generate separate OTPs for the superadmin and admin
    admin_otp = generate_otp(company_email)
    superadmin_otp = generate_otp(current_user['email'])

    print("Superadmin OTP:", superadmin_otp)
    print("Admin OTP:", admin_otp)

    # Check if an OTP record already exists for the admin email
    existing_otp_record = db.otps.find_one({"email": company_email})

    if existing_otp_record:
        # Update the existing OTP record with new OTP value and expiry time
        db.otps.update_one(
            {"email": company_email},
            {"$set": {"otp": admin_otp, "expiry": datetime.now() + timedelta(minutes=5)}}
        )
    else:
        # Store the OTP temporarily in the database
        otp_expiry = datetime.now() + timedelta(minutes=5) # Set expiry time for OTP
        db.otps.insert_one({"email": company_email, "otp": admin_otp, "expiry": otp_expiry})

    print("OTP records stored in the database")
    print(company_email)
    # Send OTPs to the superadmin and admin
    send_email(current_user['email'], "OTP Verification", f"Dear Superadmin,\n\nThank you for initiating the admin creation process. Your One-Time Password (OTP) for verification is: {superadmin_otp}\n\nPlease use this OTP to proceed with the creation process.\n\nBest regards,\n{settings.company_name}")

    send_email(company_email, "OTP Verification", f"Dear Admin,\n\nAn OTP has been generated for your admin creation process. Your One-Time Password (OTP) for verification is: {admin_otp}\n\nKindly use this OTP to complete the creation process.\n\nBest regards,\n{settings.company_name}")

    print("OTP emails sent")

    # Temporarily store the admin data
    temp_storage[company_email] = {
        'company_name': company_name,
        'industry': industry,
        'country': country,
        'state': state,
        'city': city,
        'pincode': pincode,
        'language': language,
        'website': website,
        'timezone': timezone,
        'num_employees': num_employees,
        'company_phone_number': company_phone_number,
        'password': password
    }

    return {"message": "OTPs sent to superadmin and admin for verification", "status code": 200}

@admin_router.post('/verify_otp')
async def verify_admin_creation_otp(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    
    company_email = data.get('company_email')
    superadmin_otp = data.get('superadmin_otp')
    admin_otp = data.get('admin_otp')

    # Fetch the OTP for the superadmin and admin from the database
    superadmin_otp_record = db.otps.find_one({"email": current_user['email']})
    admin_otp_record = db.otps.find_one({"email": company_email})

    # Verify the OTP for both superadmin and admin
    superadmin_otp_verified = superadmin_otp_record and superadmin_otp_record['otp'] == superadmin_otp and datetime.now() < superadmin_otp_record['expiry']
    print(superadmin_otp_verified)
    admin_otp_verified = admin_otp_record and admin_otp_record['otp'] == admin_otp and datetime.now() < admin_otp_record['expiry']
    print(admin_otp_verified)

    if superadmin_otp_verified and admin_otp_verified:
        admin_data = temp_storage.pop(company_email, None)
        print(admin_data)
        if not admin_data:
            raise HTTPException(status_code=404, detail="Admin data not found")

        # Generate a unique admin ID
        admin_id = get_next_sequence(db, 'adminid')
        password = admin_data["password"]
        hash = hashlib.sha256(password.encode()).hexdigest()

        # Create the admin user with admin_id
        user = {
            "admin_id": admin_id,
            "email": company_email,
            "password" : hash,
            "roles": ['admin'],
            "name": admin_data['company_name'],
            "company_name": admin_data['company_name'],
            "industry": admin_data['industry'],
            "country": admin_data['country'],
            "state": admin_data['state'],
            "city": admin_data['city'],
            "pincode": admin_data['pincode'],
            "language": admin_data['language'],
            "website": admin_data.get('website'),
            "timezone": admin_data['timezone'],
            "num_employees": admin_data['num_employees'],
            "company_phone_number": admin_data['company_phone_number'],
            "active_status": "true"
        }
        db.users.insert_one(user)
        print(admin_data['password'])

        # Delete the OTPs from the database
        db.otps.delete_many({"email": {"$in": [current_user['email'], company_email]}})

        # Send email to the new admin with credentials
        email_body = f"Subject: Your Admin Credentials\n\nDear {admin_data['company_name']},\n\nCongratulations! You have been successfully registered as an admin on our platform.\n\nHere are your login credentials:\nEmail: {company_email}\nPassword: {password}\n\nPlease keep your credentials secure and do not share them with anyone.\n\nIf you have any questions or need assistance, feel free to reach out to our support team at {settings.support_email} or call us at {settings.support_phone_number}.\n\nThank you for choosing us!\n\nBest Regards,\n{settings.company_name}"
        send_email(company_email, "Your Admin Credentials", email_body)

        return {"message": "Admin created successfully", "admin_id": admin_id, "status": 200}
    else:
        raise HTTPException(status_code=401, detail="Invalid or expired OTP")

@admin_router.get('/get_admins')
async def get_admins(current_user: dict = Depends(get_current_user)):
    admin_records = db.users.find({"roles": "admin"}, {"password": 0})  # Excluding password from the response
    admins = []
    for record in admin_records:
        # Convert ObjectId to string
        record['_id'] = str(record['_id'])
        admins.append(record)
    return admins

# Endpoint to retrieve login history for a specific admin
@admin_router.get('/admin_login_history/{admin_id}')
async def get_admin_login_history(admin_id: int, current_user: dict = Depends(get_current_user)):
    try:
        # Retrieve admin details
        admin_details = db.users.find_one({"admin_id": admin_id}, {"password": 0})  # Exclude password field
        if not admin_details:
            raise HTTPException(status_code=404, detail="Admin not found")

        # Retrieve login history for the specified admin ID
        login_history = list(db.admin_login_history.find({"admin_id": admin_id}))
        
        # Optionally, convert ObjectIds to strings for each document
        for login_event in login_history:
            login_event['_id'] = str(login_event['_id'])

        # Include admin details and login history in the response
        admin_details['_id'] = str(admin_details['_id'])
        admin_details['login_history'] = login_history
        
        return admin_details
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@admin_router.post('/update_admin_status')
async def update_admin_status(request: Request, current_user: dict = Depends(get_current_user)):
    data = await request.json()
    admin_id = data.get('admin_id')
    new_status = data.get('active_status')  # Assuming the new status is passed as 'active_status'
    feedback = data.get('feedback')  # Extracting feedback from request data

    # Retrieve the current admin status
    admin = db.users.find_one({"admin_id": admin_id})
    if not admin:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Admin not found")

    # Update the admin status
    old_status = admin['active_status']
    db.admin_status_history.insert_one({
        "admin_id": admin_id,
        "old_status": old_status,
        "new_status": new_status,
        "feedback": feedback,
        "timestamp": datetime.now()
    })
    db.users.update_one({"admin_id": admin_id}, {"$set": {"active_status": new_status}})

    # Construct the email body
    email_subject = "Admin Status Change Notification"
    email_body = f"Dear {admin['name']},\n\n"\
                 f"We would like to inform you that your admin status has been changed.\n"\
                 f"Old Status: {old_status}\n"\
                 f"New Status: {new_status}\n"\
                 f"Feedback/Reason: {feedback}\n\n"\
                 f"Thank you for your attention to this matter.\n\n"\
                 f"Regards,\n"\
                 f"Your Company Name"

    # Send email to respective admin with the reason for status change
    send_email(admin['email'], email_subject, email_body)

    return {"message": "Admin status updated successfully"}


@admin_router.get('/admin_status_history/{admin_id}')
async def get_admin_status_history(admin_id: str, current_user: dict = Depends(get_current_user)):
    try:
        admin_history = list(db.admin_status_history.find({"admin_id": admin_id}))
        print(admin_history)
        # Convert ObjectId to string for each document
        for history in admin_history:
            history['admin_id'] = str(history['admin_id'])
        return admin_history
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@admin_router.delete('/remove_admin/{admin_id}')
async def remove_admin(admin_id: int, current_user: dict = Depends(get_current_user)):
    # Check if the current user has the necessary permissions to remove admins
    # verify_user_role(current_user)

    # Check if the admin to be removed exists
    admin = db.users.find_one({"admin_id": admin_id})
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")

    # Remove the admin from the database
    db.users.delete_one({"admin_id": admin_id})

    return {"message": "Admin removed successfully", "status": 200}

@admin_router.post('/submit_document')
# @role_required('admin')
async def submit_document(data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    agreement_name = data.get('agreement_name')
    agreement_type = data.get('agreement_type')
    document_base64 = data.get('document')
    signers = data.get('signers', [])
    watchers = data.get('watchers', [])
    admin_id = data.get('admin_id')
    admin_record = db.users.find_one({"admin_id": admin_id})
    if not admin_record:
        raise HTTPException(status_code=404, detail="Admin not found")

    admin_email = admin_record['email']
    print(admin_email)

    # Decode and store the document
    document_id = get_next_sequence(db, 'documentid')
    document_path = save_document(document_base64, document_id)

    # Set status for signers: first one 'in_progress' and others 'pending'
    for i, signer in enumerate(signers):
        signer['status'] = 'in_progress' if i == 0 else 'pending'

    # Generate OTP and send to admin's email
    otp = generate_otp(admin_email)
    print(otp)
    email_body = f"Dear Admin,\n\nAn OTP has been generated for your account verification. Please use the following One-Time Password (OTP) to complete the verification process:\n\nOTP: {otp}\n\nIf you did not request this OTP or need further assistance, please contact us immediately.\n\nBest regards,\n{settings.name}\n{settings.role}\n{settings.support_email}"
    send_email(admin_email, "OTP Verification", email_body)

    # Temporarily store the details
    temp_storage[admin_email] = {
        "admin_id": admin_id,
        "document_id": document_id,
        "agreement_name": agreement_name,
        "agreement_type": agreement_type,
        "signers": signers, 
        "watchers": watchers,
        "document_path": document_path,
        "original_documentbase64": document_base64,
        "document_base64": document_base64
    }

    return {"message": "Details submitted. OTP sent for verification.", "document_id": document_id, "status": 200}

@admin_router.post('/verify_and_store_document')
# @role_required('admin')
async def verify_and_store_document(otp_data: dict = Body(...), current_user: dict = Depends(get_current_user)):
    admin_email = otp_data.get('email')
    otp = otp_data.get('otp')
    # temp_storage[admin_email] = admin_email
    if verify_otp(admin_email, otp):
        document_data = temp_storage.pop(admin_email, None)
        if document_data:
            # Assign unique IDs to each signer and watcher
            for signer in document_data['signers']:
                signer['signer_id'] = get_next_sequence(db, 'signerid')
            for watcher in document_data['watchers']:
                watcher['watcher_id'] = get_next_sequence(db, 'watcherid')

            # Store in DB
            insert_result = db.documents.insert_one(document_data)
            document_id = insert_result.inserted_id
            notify_watchers_about_document_creation(document_data['watchers'], document_id, document_data)
            return {"message": "Document and details stored successfully", "status": 200}
        else:
            raise HTTPException(status_code=404, detail="Session expired or invalid request")
    else:
        raise HTTPException(status_code=401, detail="Invalid or expired OTP")

@admin_router.get('/get_documents')
async def get_admin_documents(request: Request, current_user: dict = Depends(get_current_user)):
    admin_id = request.query_params.get('admin_id')  # Assuming you pass the admin ID as a query parameter
    try:
        documents = list(db.documents.find({"admin_id": int(admin_id)}))
        # Optionally, exclude certain fields from the response
        for doc in documents:
            doc.pop('_id', None)  # Remove MongoDB's _id field

        return documents
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def protected_resource(user: dict = Depends(get_current_user)):
    verify_user_role(user)


