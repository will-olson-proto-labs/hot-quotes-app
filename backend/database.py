from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from passlib.context import CryptContext
import os

# Database Configuration - SQLite for local, PostgreSQL for production
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    # Production: Use provided DATABASE_URL (Railway will provide this)
    print("Using PostgreSQL database")
    # Handle Railway's PostgreSQL URL format (postgres:// -> postgresql://)
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    engine = create_engine(DATABASE_URL)
else:
    # Local development: Use SQLite
    print("Using SQLite database for local development")
    DATABASE_URL = "sqlite:///./hot_quotes.db"
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False)  # admin, sales, analyst
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def verify_password(self, password: str) -> bool:
        return pwd_context.verify(password, self.hashed_password)
    
    @classmethod
    def hash_password(cls, password: str) -> str:
        return pwd_context.hash(password)

class Quote(Base):
    __tablename__ = "quotes"
    
    id = Column(Integer, primary_key=True, index=True)
    quote_number = Column(String(100), nullable=False, unique=True)
    reason_for_hot = Column(String(50), nullable=False)
    reason_other_text = Column(String(255), nullable=True)  # For "other" reason
    additional_info = Column(Text, nullable=False)
    special_process = Column(String(50), nullable=False)
    subject_line = Column(String(200), nullable=True)
    additional_cc_emails = Column(Text, nullable=True)  # JSON string of email list
    file_path = Column(String(500), nullable=True)  # Path to uploaded file
    original_filename = Column(String(255), nullable=True)  # Original uploaded filename
    status = Column(String(20), default="available")  # available, claimed, completed
    priority = Column(String(10), default="normal")  # normal, high, urgent
    submitted_by = Column(String(50), nullable=False)  # username who submitted
    claimed_by = Column(String(50), nullable=True)    # username who claimed
    created_at = Column(DateTime, default=datetime.utcnow)
    claimed_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)

# Database initialization function
def init_database():
    """Initialize database tables and create default users if needed."""
    try:
        # Create tables
        Base.metadata.create_all(bind=engine)
        print("Database tables created successfully")
        
        # Create default users
        create_default_users()
        
    except Exception as e:
        print(f"Database initialization error: {e}")
        raise

# Create default admin user if it doesn't exist
def create_default_users():
    """Create default users for the system."""
    db = SessionLocal()
    try:
        # Check if any users exist
        existing_users = db.query(User).first()
        if not existing_users:
            # Create default admin
            admin = User(
                username="admin",
                email="admin@company.com",
                full_name="System Administrator",
                hashed_password=User.hash_password("admin123"),
                role="admin"
            )
            db.add(admin)
            
            # Create sample users
            sales_user = User(
                username="sales_demo",
                email="sales@company.com",
                full_name="Sales Demo User",
                hashed_password=User.hash_password("sales123"),
                role="sales"
            )
            db.add(sales_user)
            
            analyst_user = User(
                username="analyst_demo",
                email="analyst@company.com", 
                full_name="Analyst Demo User",
                hashed_password=User.hash_password("analyst123"),
                role="analyst"
            )
            db.add(analyst_user)
            
            db.commit()
            print("Default users created:")
            print("Admin: admin / admin123")
            print("Sales: sales_demo / sales123") 
            print("Analyst: analyst_demo / analyst123")
        else:
            print("Users already exist, skipping default user creation")
            
    except Exception as e:
        db.rollback()
        print(f"Error creating default users: {e}")
        raise
    finally:
        db.close()

# Database health check function
def check_database_connection():
    """Check if database connection is working."""
    try:
        db = SessionLocal()
        # Try a simple query - using text() for explicit SQL
        if DATABASE_URL and not DATABASE_URL.startswith("sqlite"):
            # PostgreSQL
            db.execute(text("SELECT 1"))
        else:
            # SQLite
            db.execute(text("SELECT 1"))
        db.close()
        return True
    except Exception as e:
        print(f"Database connection failed: {e}")
        return False