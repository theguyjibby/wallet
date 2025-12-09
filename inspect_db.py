"""
Database Inspection Script
Works with both SQLite (local) and PostgreSQL (Render)
"""

import os
from dotenv import load_dotenv

load_dotenv()

def inspect_database():
    """Inspect database and show all tables and their schemas"""
    database_url = os.getenv('DATABASE_URL') or os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///web33.db')
    
    # Fix Render's postgres:// to postgresql://
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    print(f"Connecting to database: {database_url[:50]}...\n")
    
    try:
        from sqlalchemy import create_engine, inspect
        
        engine = create_engine(database_url)
        inspector = inspect(engine)
        
        tables = inspector.get_table_names()
        print(f"[SUCCESS] Found {len(tables)} tables:\n")
        
        for table_name in tables:
            print(f"[TABLE] {table_name}")
            columns = inspector.get_columns(table_name)
            
            for col in columns:
                nullable = "NULL" if col['nullable'] else "NOT NULL"
                print(f"  - {col['name']}: {col['type']} {nullable}")
            print()
        
        if not tables:
            print("[WARNING] No tables found. Run init_db.py to create tables.")
    
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    inspect_database()
