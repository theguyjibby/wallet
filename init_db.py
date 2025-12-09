"""
Database Initialization Script for PostgreSQL on Render

This script creates all necessary tables in your PostgreSQL database.
It can be run locally or on Render.

Usage:
    python init_db.py
"""

from web333 import app, db
import os

def init_database():
    """Initialize the database with all tables"""
    with app.app_context():
        try:
            # Create all tables defined in the models
            db.create_all()
            print("[SUCCESS] Database tables created successfully!")
            print("\nTables created:")
            print("  - user (User accounts)")
            print("  - account (Wallet accounts)")
            print("  - transactions (Transaction history)")
            
            # Verify tables were created
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            print(f"\nVerified tables in database: {tables}")
            
        except Exception as e:
            print(f"[ERROR] Error creating database tables: {e}")
            raise

if __name__ == "__main__":
    database_url = os.getenv('DATABASE_URL') or os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///web33.db')
    print(f"Connecting to database: {database_url[:50]}...")
    
    init_database()