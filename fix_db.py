import sqlite3

# Connect to the database
conn = sqlite3.connect('instance/web33.db')
cursor = conn.cursor()

try:
    # Add the is_sent column
    # Default to 1 (True) for existing sent transactions
    cursor.execute("ALTER TABLE transactions ADD COLUMN is_sent BOOLEAN DEFAULT 1")
    conn.commit()
    print("Successfully added 'is_sent' column to 'transactions' table.")
except sqlite3.OperationalError as e:
    if "duplicate column name" in str(e):
        print("Column 'is_sent' already exists.")
    elif "no such table" in str(e):
        print("Table 'transactions' does not exist in instance/web33.db. The app will create it automatically when you run it.")
    else:
        print(f"An error occurred: {e}")
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    conn.close()
