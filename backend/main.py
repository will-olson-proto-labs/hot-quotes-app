from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from contextlib import asynccontextmanager
import jwt
from jwt import PyJWTError
import re
import json
import os
import shutil
import uuid
import logging

from database import SessionLocal, Quote, User, init_database, check_database_connection
from models import (QuoteCreate, QuoteResponse, QuoteUpdate, 
                   UserCreate, UserLogin, UserResponse, UserUpdate, Token, SelfRegister)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 hours

# File upload configuration
UPLOAD_DIR = "uploads"
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
ALLOWED_EXTENSIONS = {".pdf", ".doc", ".docx", ".txt", ".jpg", ".jpeg", ".png", ".zip", ".rar"}

# Create upload directory if it doesn't exist
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Initialize with sample data
def init_sample_data(db: Session):
    """Initialize sample data if none exists."""
    try:
        if db.query(Quote).first() is None:
            sample_quotes = [
                Quote(
                    quote_number="HQ-2024-001",
                    reason_for_hot="cutoff/order asap",
                    additional_info="Customer needs urgent delivery for production line",
                    special_process="standard",
                    subject_line="Urgent: Production parts needed",
                    priority="high",
                    submitted_by="sales_demo"
                ),
                Quote(
                    quote_number="HQ-2024-002",
                    reason_for_hot="design review",
                    additional_info="Need design review for complex geometry before production",
                    special_process="mold mod",
                    priority="normal",
                    submitted_by="sales_demo"
                )
            ]
            for quote in sample_quotes:
                db.add(quote)
            db.commit()
            logger.info("Sample quotes created")
        else:
            logger.info("Sample quotes already exist, skipping creation")
    except SQLAlchemyError as e:
        logger.error(f"Error creating sample data: {e}")
        db.rollback()

# Lifespan event handler (replaces @app.on_event("startup"))
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting up Hot Quotes Management System")
    
    try:
        # Check database connection
        if not check_database_connection():
            logger.error("Failed to connect to database")
            raise Exception("Database connection failed")
        
        # Initialize database
        init_database()
        
        # Initialize sample data
        db = SessionLocal()
        try:
            init_sample_data(db)
        finally:
            db.close()
            
        logger.info("Application startup completed successfully")
        
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Hot Quotes Management System")

app = FastAPI(
    title="Hot Quotes Management System", 
    description="A comprehensive system for managing hot quotes in manufacturing",
    version="1.0.0",
    lifespan=lifespan
)
security = HTTPBearer()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files
app.mount("/static", StaticFiles(directory="../frontend"), name="static")

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except PyJWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# Role-based permission functions
def require_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

def require_sales_or_admin(current_user: User = Depends(get_current_user)):
    if current_user.role not in ["sales", "admin"]:
        raise HTTPException(status_code=403, detail="Sales or Admin access required")
    return current_user

def require_analyst_or_admin(current_user: User = Depends(get_current_user)):
    if current_user.role not in ["analyst", "admin"]:
        raise HTTPException(status_code=403, detail="Analyst or Admin access required")
    return current_user

# Helper function to generate username from email
def generate_username_from_email(email: str, db: Session) -> str:
    # Extract first.last from email
    email_part = email.split('@')[0]
    base_username = email_part.replace('.', '_')
    
    # Check if username exists and handle duplicates
    username = base_username
    counter = 1
    while db.query(User).filter(User.username == username).first():
        username = f"{base_username}_{counter}"
        counter += 1
    
    return username

# Helper function to generate full name from email
def generate_full_name_from_email(email: str) -> str:
    # Extract first.last from email and capitalize
    email_part = email.split('@')[0]
    first, last = email_part.split('.')
    return f"{first.capitalize()} {last.capitalize()}"

# Helper function to validate protolabs email
def validate_protolabs_email(email: str) -> bool:
    pattern = r'^[a-zA-Z]+\.[a-zA-Z]+@protolabs\.com$'
    return bool(re.match(pattern, email))

# File upload helper
def save_uploaded_file(file: UploadFile) -> tuple[str, str]:
    # Check file size
    file.file.seek(0, 2)  # Seek to end
    file_size = file.file.tell()
    file.file.seek(0)  # Reset to beginning
    
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large")
    
    # Check file extension
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="File type not allowed")
    
    # Generate unique filename
    unique_filename = f"{uuid.uuid4()}{file_ext}"
    file_path = os.path.join(UPLOAD_DIR, unique_filename)
    
    # Save file
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    return file_path, file.filename

# API Routes

@app.get("/")
async def root():
    return {"message": "Hot Quotes Management System API"}

@app.get("/health")
async def health_check():
    """Health check endpoint for Railway deployment."""
    try:
        db_healthy = check_database_connection()
        return {
            "status": "healthy" if db_healthy else "unhealthy",
            "database": "connected" if db_healthy else "disconnected",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        return {
            "status": "unhealthy", 
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

# Authentication routes
@app.post("/api/auth/login", response_model=Token)
def login(user_credentials: UserLogin, db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.username == user_credentials.username).first()
        if not user or not user.verify_password(user_credentials.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )
        if not user.is_active:
            raise HTTPException(status_code=400, detail="Inactive user")
        
        access_token = create_access_token(data={"sub": user.username})
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user
        }
    except SQLAlchemyError as e:
        logger.error(f"Database error during login: {e}")
        raise HTTPException(status_code=500, detail="Database error occurred")

# New self-registration endpoint (public) - UPDATED TO INCLUDE ROLE CHOICE
@app.post("/api/auth/self-register", response_model=UserResponse)
def self_register(registration_data: SelfRegister, db: Session = Depends(get_db)):
    try:
        # Validate email format
        if not validate_protolabs_email(registration_data.email):
            raise HTTPException(
                status_code=400, 
                detail="Email must be in the format first.last@protolabs.com"
            )
        
        # Validate role - only allow sales or analyst for self-registration
        if registration_data.role not in ["sales", "analyst"]:
            raise HTTPException(
                status_code=400,
                detail="Role must be either 'sales' or 'analyst'"
            )
        
        # Check if email already exists
        if db.query(User).filter(User.email == registration_data.email).first():
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Generate username and full name from email
        username = generate_username_from_email(registration_data.email, db)
        full_name = generate_full_name_from_email(registration_data.email)
        
        # Create new user with selected role
        hashed_password = User.hash_password(registration_data.password)
        db_user = User(
            username=username,
            email=registration_data.email,
            full_name=full_name,
            hashed_password=hashed_password,
            role=registration_data.role  # Use selected role instead of default
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail="Invalid email format")
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error during registration: {e}")
        raise HTTPException(status_code=500, detail="Error creating account")

@app.post("/api/auth/register", response_model=UserResponse)
def register(user_data: UserCreate, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        # Check if user already exists
        if db.query(User).filter(User.username == user_data.username).first():
            raise HTTPException(status_code=400, detail="Username already exists")
        if db.query(User).filter(User.email == user_data.email).first():
            raise HTTPException(status_code=400, detail="Email already exists")
        
        # Create new user
        hashed_password = User.hash_password(user_data.password)
        db_user = User(
            username=user_data.username,
            email=user_data.email,
            full_name=user_data.full_name,
            hashed_password=hashed_password,
            role=user_data.role
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error during user creation: {e}")
        raise HTTPException(status_code=500, detail="Error creating user")

@app.get("/api/auth/me", response_model=UserResponse)
def get_current_user_info(current_user: User = Depends(get_current_user)):
    return current_user

# User management (admin only)
@app.get("/api/users/", response_model=List[UserResponse])
def get_all_users(current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        return db.query(User).all()
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching users: {e}")
        raise HTTPException(status_code=500, detail="Error fetching users")

@app.put("/api/users/{user_id}/role", response_model=UserResponse)
def update_user_role(user_id: int, user_update: UserUpdate, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        # Get the user to update
        user_to_update = db.query(User).filter(User.id == user_id).first()
        if not user_to_update:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Validate the new role
        if user_update.role not in ["admin", "sales", "analyst"]:
            raise HTTPException(status_code=400, detail="Invalid role. Must be admin, sales, or analyst")
        
        # Prevent admin from changing their own role (safety measure)
        if user_to_update.id == current_user.id:
            raise HTTPException(status_code=400, detail="Cannot change your own role")
        
        # Update the role
        user_to_update.role = user_update.role
        db.commit()
        db.refresh(user_to_update)
        return user_to_update
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error updating user role: {e}")
        raise HTTPException(status_code=500, detail="Error updating user role")

@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        # Get the user to delete
        user_to_delete = db.query(User).filter(User.id == user_id).first()
        if not user_to_delete:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Prevent admin from deleting themselves
        if user_to_delete.id == current_user.id:
            raise HTTPException(status_code=400, detail="Cannot delete your own account")
        
        # Check if user has submitted quotes that are still in progress
        active_quotes = db.query(Quote).filter(
            Quote.submitted_by == user_to_delete.username,
            Quote.status.in_(["available", "claimed"])
        ).first()
        
        if active_quotes:
            raise HTTPException(
                status_code=400, 
                detail="Cannot delete user with active quotes. Please complete or reassign their quotes first."
            )
        
        # Check if user has claimed quotes
        claimed_quotes = db.query(Quote).filter(
            Quote.claimed_by == user_to_delete.username,
            Quote.status == "claimed"
        ).first()
        
        if claimed_quotes:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete user with claimed quotes. Please reassign their claims first."
            )
        
        # Delete the user
        db.delete(user_to_delete)
        db.commit()
        return {"message": f"User {user_to_delete.username} has been deleted successfully"}
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error deleting user: {e}")
        raise HTTPException(status_code=500, detail="Error deleting user")

# Quote routes with file upload support
@app.post("/api/quotes/", response_model=QuoteResponse)
async def create_quote(
    quote_number: str = Form(...),
    reason_for_hot: str = Form(...),
    reason_other_text: Optional[str] = Form(None),
    additional_info: str = Form(...),
    special_process: str = Form(...),
    subject_line: Optional[str] = Form(None),
    additional_cc_emails: Optional[str] = Form("[]"),  # JSON string
    priority: str = Form("normal"),
    file: Optional[UploadFile] = File(None),
    current_user: User = Depends(require_sales_or_admin),
    db: Session = Depends(get_db)
):
    try:
        # Check if quote number already exists
        existing_quote = db.query(Quote).filter(Quote.quote_number == quote_number).first()
        if existing_quote:
            raise HTTPException(status_code=400, detail="Quote number already exists")
        
        # Parse CC emails
        try:
            cc_emails_list = json.loads(additional_cc_emails) if additional_cc_emails else []
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid CC emails format")
        
        # Handle file upload
        file_path = None
        original_filename = None
        if file and file.filename:
            file_path, original_filename = save_uploaded_file(file)
        
        # Create quote
        db_quote = Quote(
            quote_number=quote_number,
            reason_for_hot=reason_for_hot,
            reason_other_text=reason_other_text,
            additional_info=additional_info,
            special_process=special_process,
            subject_line=subject_line,
            additional_cc_emails=json.dumps(cc_emails_list),
            file_path=file_path,
            original_filename=original_filename,
            priority=priority,
            submitted_by=current_user.username
        )
        
        db.add(db_quote)
        db.commit()
        db.refresh(db_quote)
        return db_quote
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error creating quote: {e}")
        raise HTTPException(status_code=500, detail="Error creating quote")

@app.get("/api/quotes/", response_model=List[QuoteResponse])
def get_quotes(status: str = None, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        query = db.query(Quote)
        
        # Role-based filtering
        if current_user.role == "sales":
            query = query.filter(Quote.submitted_by == current_user.username)
        
        if status:
            query = query.filter(Quote.status == status)
        return query.order_by(Quote.created_at.desc()).all()
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching quotes: {e}")
        raise HTTPException(status_code=500, detail="Error fetching quotes")

@app.get("/api/quotes/available", response_model=List[QuoteResponse])
def get_available_quotes(current_user: User = Depends(require_analyst_or_admin), db: Session = Depends(get_db)):
    try:
        return db.query(Quote).filter(Quote.status == "available").order_by(Quote.priority.desc(), Quote.created_at.asc()).all()
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching available quotes: {e}")
        raise HTTPException(status_code=500, detail="Error fetching available quotes")

@app.get("/api/quotes/claimed-by/{analyst_username}", response_model=List[QuoteResponse])
def get_claimed_quotes(analyst_username: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        # Users can only see their own claims unless they're admin
        if current_user.role != "admin" and current_user.username != analyst_username:
            raise HTTPException(status_code=403, detail="Can only view your own claims")
        
        return db.query(Quote).filter(
            Quote.claimed_by == analyst_username,
            Quote.status == "claimed"
        ).order_by(Quote.claimed_at.desc()).all()
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching claimed quotes: {e}")
        raise HTTPException(status_code=500, detail="Error fetching claimed quotes")

@app.get("/api/quotes/completed", response_model=List[QuoteResponse])
def get_completed_quotes(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        query = db.query(Quote).filter(Quote.status == "completed")
        
        # Role-based filtering
        if current_user.role == "sales":
            query = query.filter(Quote.submitted_by == current_user.username)
        elif current_user.role == "analyst":
            query = query.filter(Quote.claimed_by == current_user.username)
        
        return query.order_by(Quote.completed_at.desc()).all()
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching completed quotes: {e}")
        raise HTTPException(status_code=500, detail="Error fetching completed quotes")

# File download endpoint
@app.get("/api/quotes/{quote_id}/download")
def download_file(quote_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        quote = db.query(Quote).filter(Quote.id == quote_id).first()
        if not quote:
            raise HTTPException(status_code=404, detail="Quote not found")
        
        # Check permissions
        if current_user.role == "sales" and quote.submitted_by != current_user.username:
            raise HTTPException(status_code=403, detail="Access denied")
        
        if not quote.file_path or not os.path.exists(quote.file_path):
            raise HTTPException(status_code=404, detail="File not found")
        
        return FileResponse(
            path=quote.file_path,
            filename=quote.original_filename,
            media_type='application/octet-stream'
        )
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching quote for download: {e}")
        raise HTTPException(status_code=500, detail="Error fetching quote")

@app.post("/api/quotes/{quote_id}/claim")
def claim_quote(quote_id: int, current_user: User = Depends(require_analyst_or_admin), db: Session = Depends(get_db)):
    try:
        quote = db.query(Quote).filter(Quote.id == quote_id).first()
        if not quote:
            raise HTTPException(status_code=404, detail="Quote not found")
        if quote.status != "available":
            raise HTTPException(status_code=400, detail="Quote is not available")
        
        quote.status = "claimed"
        quote.claimed_by = current_user.username
        quote.claimed_at = datetime.now(timezone.utc)
        db.commit()
        return {"message": "Quote claimed successfully"}
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error claiming quote: {e}")
        raise HTTPException(status_code=500, detail="Error claiming quote")

@app.post("/api/quotes/{quote_id}/unclaim")
def unclaim_quote(quote_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        quote = db.query(Quote).filter(Quote.id == quote_id).first()
        if not quote:
            raise HTTPException(status_code=404, detail="Quote not found")
        if quote.status != "claimed":
            raise HTTPException(status_code=400, detail="Quote is not claimed")
        
        # Users can only unclaim their own quotes unless they're admin
        if current_user.role != "admin" and quote.claimed_by != current_user.username:
            raise HTTPException(status_code=403, detail="Can only unclaim your own quotes")
        
        quote.status = "available"
        quote.claimed_by = None
        quote.claimed_at = None
        db.commit()
        return {"message": "Quote unclaimed successfully"}
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error unclaiming quote: {e}")
        raise HTTPException(status_code=500, detail="Error unclaiming quote")

@app.post("/api/quotes/{quote_id}/complete")
def complete_quote(quote_id: int, completion_notes: str = "", current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        quote = db.query(Quote).filter(Quote.id == quote_id).first()
        if not quote:
            raise HTTPException(status_code=404, detail="Quote not found")
        if quote.status != "claimed":
            raise HTTPException(status_code=400, detail="Quote is not claimed")
        
        # Users can only complete their own quotes unless they're admin
        if current_user.role != "admin" and quote.claimed_by != current_user.username:
            raise HTTPException(status_code=403, detail="Can only complete your own quotes")
        
        quote.status = "completed"
        quote.completed_at = datetime.now(timezone.utc)
        if completion_notes:
            quote.notes = completion_notes
        db.commit()
        return {"message": "Quote completed successfully"}
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error completing quote: {e}")
        raise HTTPException(status_code=500, detail="Error completing quote")

@app.get("/api/analytics/summary")
def get_analytics_summary(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        base_query = db.query(Quote)
        
        # Role-based filtering for analytics
        if current_user.role == "sales":
            base_query = base_query.filter(Quote.submitted_by == current_user.username)
        elif current_user.role == "analyst":
            # Analysts see all available quotes + their own claimed/completed
            available = db.query(Quote).filter(Quote.status == "available").count()
            claimed = db.query(Quote).filter(Quote.claimed_by == current_user.username, Quote.status == "claimed").count()
            completed = db.query(Quote).filter(Quote.claimed_by == current_user.username, Quote.status == "completed").count()
            total = available + claimed + completed
            return {
                "total_quotes": total,
                "available_quotes": available,
                "claimed_quotes": claimed,
                "completed_quotes": completed,
                "my_claims": claimed
            }
        
        # Admin and sales get full counts (sales filtered to their submissions)
        total_quotes = base_query.count()
        available_quotes = base_query.filter(Quote.status == "available").count()
        claimed_quotes = base_query.filter(Quote.status == "claimed").count()
        completed_quotes = base_query.filter(Quote.status == "completed").count()
        
        result = {
            "total_quotes": total_quotes,
            "available_quotes": available_quotes,
            "claimed_quotes": claimed_quotes,
            "completed_quotes": completed_quotes
        }
        
        # Add personal stats for analysts
        if current_user.role in ["analyst", "admin"]:
            my_claims = db.query(Quote).filter(Quote.claimed_by == current_user.username, Quote.status == "claimed").count()
            result["my_claims"] = my_claims
        
        return result
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching analytics: {e}")
        raise HTTPException(status_code=500, detail="Error fetching analytics")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)