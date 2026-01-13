import os
import sqlite3

from datetime import datetime
# 'time' import removed as it was only used for connection retries
# 'psycopg2' and 'pool' imports replaced with 'sqlite3'

# Configuration for SQLite
# We only need a file path.
DB_FILE = os.getenv('DB_FILE', 'vulnerable_bank.db')

# Connection pooling is not typically used with SQLite in this manner.
# We will create and close connections as needed.

def get_connection():
    """
    Get a connection to the SQLite database.
    Enables foreign key support.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn
    except Exception as e:
        print(f"Failed to connect to SQLite database at {DB_FILE}: {e}")
        raise e

def return_connection(connection):
    """
    Close the SQLite connection.
    """
    if connection:
        connection.close()

def init_db():
    """
    Initialize database tables
    Multiple vulnerabilities present for learning purposes
    """
    conn = get_connection()
    try:
        with conn: # Use 'with' to automatically handle commit/rollback
            cursor = conn.cursor()
            
            # Create users table
            # - SERIAL -> INTEGER PRIMARY KEY AUTOINCREMENT
            # - DECIMAL -> REAL
            # - BOOLEAN -> INTEGER
            # - TEXT -> TEXT (unchanged)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,  -- Vulnerability: Passwords stored in plaintext
                    account_number TEXT NOT NULL UNIQUE,
                    balance REAL DEFAULT 1000.0,
                    is_admin INTEGER DEFAULT 0, -- 0 for FALSE
                    profile_picture TEXT,
                    reset_pin TEXT  -- Vulnerability: Reset PINs stored in plaintext
                )
            ''')
            
            # Create loans table
            # - DECIMAL -> REAL
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS loans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    amount REAL,
                    status TEXT DEFAULT 'pending'
                )
            ''')
            
            # Create transactions table
            # - DECIMAL -> REAL
            # - TIMESTAMP -> TEXT (or INTEGER, but TEXT is common for CURRENT_TIMESTAMP)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_account TEXT NOT NULL,
                    to_account TEXT NOT NULL,
                    amount REAL NOT NULL,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    transaction_type TEXT NOT NULL,
                    description TEXT
                )
            ''')
            
            # Create virtual cards table
            # - DECIMAL -> REAL
            # - BOOLEAN -> INTEGER
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS virtual_cards (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    card_number TEXT NOT NULL UNIQUE,  -- Vulnerability: Card numbers stored in plaintext
                    cvv TEXT NOT NULL,  -- Vulnerability: CVV stored in plaintext
                    expiry_date TEXT NOT NULL,
                    card_limit REAL DEFAULT 1000.0,
                    current_balance REAL DEFAULT 0.0,
                    is_frozen INTEGER DEFAULT 0, -- 0 for FALSE
                    is_active INTEGER DEFAULT 1, -- 1 for TRUE
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_used_at TEXT,
                    card_type TEXT DEFAULT 'standard'  -- Vulnerability: No validation on card type
                )
            ''')

            # Create virtual card transactions table
            # - DECIMAL -> REAL
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS card_transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    card_id INTEGER REFERENCES virtual_cards(id) ON DELETE CASCADE,
                    amount REAL NOT NULL,
                    merchant_name TEXT,  -- Vulnerability: No input validation
                    transaction_type TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    description TEXT
                )
            ''')
            
            # Create default admin account if it doesn't exist
            # - Changed placeholder from %s to ?
            # - Changed boolean 'True' to integer 1
            cursor.execute("SELECT * FROM users WHERE username='admin'")
            if not cursor.fetchone():
                cursor.execute(
                    """
                    INSERT INTO users (username, password, account_number, balance, is_admin) 
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    ('admin', 'admin123', 'ADMIN001', 1000000.0, 1) # True -> 1
                )
            # Create some user
            cursor.execute("SELECT * FROM users WHERE username='alice'")
            if not cursor.fetchone():
                cursor.execute(
                    """
                    INSERT INTO users (username, password, account_number, balance, is_admin) 
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    ('alice', 'password', '0869065552', 1250.0, 0)
                )
            cursor.execute("SELECT * FROM users WHERE username='bob'")
            if not cursor.fetchone():
                cursor.execute(
                    """
                    INSERT INTO users (username, password, account_number, balance, is_admin) 
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    ('bob', 'password', '6955215471', 700.0, 0)
                )
            
            # Create bill categories table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS bill_categories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    is_active INTEGER DEFAULT 1 -- 1 for TRUE
                )
            ''')
            # Create billers table
            # - DECIMAL -> REAL
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS billers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category_id INTEGER REFERENCES bill_categories(id),
                    name TEXT NOT NULL,
                    account_number TEXT NOT NULL,  -- Vulnerability: No encryption
                    description TEXT,
                    minimum_amount REAL DEFAULT 0,
                    maximum_amount REAL,  -- Vulnerability: No validation
                    is_active INTEGER DEFAULT 1 -- 1 for TRUE
                )
            ''')

            # Create bill payments table
            # - DECIMAL -> REAL
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS bill_payments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    biller_id INTEGER REFERENCES billers(id),
                    amount REAL NOT NULL,
                    payment_method TEXT NOT NULL,  -- 'balance' or 'virtual_card'
                    card_id INTEGER REFERENCES virtual_cards(id),  -- NULL if paid with balance
                    reference_number TEXT,  -- Vulnerability: No unique constraint
                    status TEXT DEFAULT 'pending',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    processed_at TEXT,
                    description TEXT
                )
            ''')

            # Insert default bill categories
            # - ON CONFLICT syntax is compatible with SQLite
            cursor.execute("""
                INSERT INTO bill_categories (name, description) 
                VALUES 
                ('Utilities', 'Water, Electricity, Gas bills'),
                ('Telecommunications', 'Phone, Internet, Cable TV'),
                ('Insurance', 'Life, Health, Auto insurance'),
                ('Credit Cards', 'Credit card bill payments')
                ON CONFLICT (name) DO NOTHING
            """)

            # Insert sample billers
            # - ON CONFLICT (id) DO NOTHING for SQLite to avoid errors on re-run
            #   (Assuming name should be unique, but schema uses id. 
            #   Using 'ON CONFLICT DO NOTHING' as in original)
            cursor.execute("""
                INSERT OR IGNORE INTO billers (category_id, name, account_number, description, minimum_amount) 
                VALUES 
                (1, 'City Water', 'WATER001', 'City Water Utility', 10),
                (1, 'PowerGen Electric', 'POWER001', 'Electricity Provider', 20),
                (2, 'TeleCom Services', 'TEL001', 'Phone and Internet', 25),
                (2, 'CableTV Plus', 'CABLE001', 'Cable TV Services', 30),
                (3, 'HealthFirst Insurance', 'INS001', 'Health Insurance', 100),
                (4, 'Universal Bank Card', 'CC001', 'Credit Card Payments', 50)
            """)

            # Insert some data
            # - ON CONFLICT syntax is compatible with SQLite
            cursor.execute("""
                INSERT OR IGNORE INTO bill_payments ("id", "user_id", "biller_id", "amount", "payment_method", "card_id", "reference_number", "status", "created_at", "processed_at", "description") 
                VALUES 
                (1, 2, 4, 50, 'balance', NULL, 'BILL1763215177', 'pending', '2025-11-15 13:59:37', NULL, 'Bill Payment'),
                (2, 3, 5, 500, 'balance', NULL, 'BILL1763215225', 'pending', '2025-11-15 14:00:25', NULL, 'Bill Payment')
                ON CONFLICT (id) DO NOTHING
            """)
            cursor.execute("""
                INSERT OR IGNORE INTO transactions ("id", "from_account", "to_account", "amount", "timestamp", "transaction_type", "description")
                VALUES
                (1, '0869065552', '6955215471', 200, '2025-11-15 13:59:01', 'transfer', 'Meal')
            """)
            cursor.execute("""
                INSERT OR IGNORE INTO virtual_cards ("id", "user_id", "card_number", "cvv", "expiry_date", "card_limit", "current_balance", "is_frozen", "is_active", "created_at", "last_used_at", "card_type")
                VALUES
                (1, 2, '2537791962167271', '157', '11/26', 1000, 0, 0, 1, '2025-11-15 13:59:21', NULL, 'standard'),
                (2, 3, '6424135982319027', '636', '11/26', 2000, 0, 0, 1, '2025-11-15 14:00:06', NULL, 'premium')
            """)
            cursor.execute("""
            INSERT OR IGNORE INTO loans ("id", "user_id", "amount", "status")
            VALUES
            (1, 2, 500, 'approved')
            """)

            # Create account_statements table for BOLA demo
            # This stores monthly statement summaries
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS account_statements (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    month TEXT NOT NULL,  -- Format: YYYY-MM
                    opening_balance REAL,
                    closing_balance REAL,
                    total_credits REAL,
                    total_debits REAL,
                    statement_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    notes TEXT  -- Vulnerability: May contain sensitive info
                )
            ''')

            # Insert sample statements for BOLA demo
            cursor.execute("""
                INSERT OR IGNORE INTO account_statements
                ("id", "user_id", "month", "opening_balance", "closing_balance", "total_credits", "total_debits", "notes")
                VALUES
                (1, 2, '2025-10', 1000.0, 1250.0, 500.0, 250.0, 'Salary deposit from Acme Corp'),
                (2, 2, '2025-11', 1250.0, 1450.0, 400.0, 200.0, 'Bonus payment received'),
                (3, 3, '2025-10', 500.0, 700.0, 300.0, 100.0, 'Freelance payment - Project Alpha'),
                (4, 3, '2025-11', 700.0, 850.0, 250.0, 100.0, 'Consulting fee - Bob Smith LLC'),
                (5, 1, '2025-10', 950000.0, 1000000.0, 100000.0, 50000.0, 'Admin account - system transfers'),
                (6, 1, '2025-11', 1000000.0, 1000000.0, 50000.0, 50000.0, 'Monthly reconciliation')
            """)

            # Add more transactions for realistic demo data
            cursor.execute("""
                INSERT OR IGNORE INTO transactions ("id", "from_account", "to_account", "amount", "timestamp", "transaction_type", "description")
                VALUES
                (2, '6955215471', '0869065552', 50, '2025-11-16 09:30:00', 'transfer', 'Coffee money'),
                (3, '0869065552', 'ADMIN001', 100, '2025-11-17 14:20:00', 'transfer', 'Service fee'),
                (4, 'EXTERNAL001', '0869065552', 500, '2025-11-18 10:00:00', 'deposit', 'Salary November'),
                (5, 'EXTERNAL002', '6955215471', 300, '2025-11-18 11:30:00', 'deposit', 'Freelance payment'),
                (6, '6955215471', 'UTILITIES01', 75, '2025-11-19 08:00:00', 'payment', 'Electric bill'),
                (7, '0869065552', 'LANDLORD01', 800, '2025-11-20 09:00:00', 'payment', 'Rent payment')
            """)

            # conn.commit() is handled by the 'with conn:' block
            print("Database initialized successfully")
            
    except Exception as e:
        # Vulnerability: Detailed error information exposed
        print(f"Error initializing database: {e}")
        # conn.rollback() is handled by the 'with conn:' block
        raise e
    finally:
        return_connection(conn)

def execute_query(query, params=None, fetch=True):
    """
    Execute a database query
    Vulnerability: This function still allows for SQL injection if called with string formatting
    - Changed placeholder logic for sqlite3
    """
    conn = get_connection()
    try:
        # Using 'with conn' ensures automatic commit on success or rollback on error
        with conn:
            cursor = conn.cursor()
            
            # Use empty tuple if params is None, as required by sqlite3
            cursor.execute(query, params if params else ())
            
            result = None
            if fetch:
                result = cursor.fetchall()
            return result
            
        # Note: The original's specific commit logic for INSERT/UPDATE/DELETE
        # is now handled more robustly by the 'with conn:' context manager,
        # which commits any changes if no exception occurs.
            
    except Exception as e:
        # Vulnerability: Error details might be exposed to users
        # Rollback is handled by 'with conn:'
        print(f"Error executing query: {e}") # Added print for clarity
        raise e
    finally:
        return_connection(conn)

def execute_transaction(queries_and_params):
    """
    Execute multiple queries in a transaction
    Vulnerability: No input validation on queries
    queries_and_params: list of tuples (query, params)
    - Placeholders are now '?' (handled in the query string itself)
    """
    conn = get_connection()
    try:
        # 'with conn' manages the transaction (commit/rollback)
        with conn:
            cursor = conn.cursor()
            for query, params in queries_and_params:
                cursor.execute(query, params if params else ())
    except Exception as e:
        # Vulnerability: Transaction rollback exposed
        # Rollback handled by 'with conn'
        print(f"Error in transaction: {e}") # Added print for clarity
        raise e
    finally:
        return_connection(conn)