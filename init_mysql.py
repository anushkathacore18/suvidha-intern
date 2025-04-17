import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

def create_database():
    try:
        # Get MySQL credentials from environment variables
        mysql_user = os.getenv('MYSQL_USER', 'root')
        mysql_password = os.getenv('MYSQL_PASSWORD', 'Ombadade55555')
        mysql_host = os.getenv('MYSQL_HOST', 'localhost')
        
        print(f"Attempting to connect to MySQL with user: {mysql_user}")
        
        # Connect to MySQL server
        connection = mysql.connector.connect(
            host=mysql_host,
            user=mysql_user,
            password=mysql_password
        )
        
        if connection.is_connected():
            print("Successfully connected to MySQL server")
            cursor = connection.cursor()
            
            # Create database if it doesn't exist
            cursor.execute("CREATE DATABASE IF NOT EXISTS internship_db")
            print("Database 'internship_db' created successfully")
            
            # Use the database
            cursor.execute("USE internship_db")
            
            # Drop existing table if it exists (for clean slate)
            cursor.execute("DROP TABLE IF EXISTS user")
            
            # Create user table with increased password_hash length
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(80) UNIQUE NOT NULL,
                    email VARCHAR(120) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    user_type VARCHAR(20) NOT NULL,
                    first_name VARCHAR(50),
                    last_name VARCHAR(50),
                    institute VARCHAR(100),
                    department VARCHAR(100),
                    company_name VARCHAR(100),
                    company_website VARCHAR(200),
                    is_active BOOLEAN DEFAULT TRUE,
                    is_verified BOOLEAN DEFAULT FALSE,
                    requires_password_reset BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_by INT
                )
            """)
            print("User table created successfully")
            
            # Create super admin
            from werkzeug.security import generate_password_hash
            password_hash = generate_password_hash('admin123')
            
            cursor.execute("""
                INSERT INTO user (
                    username, email, password_hash, user_type, 
                    first_name, last_name, is_active, is_verified
                ) VALUES (
                    'admin', 'admin@example.com', %s, 'super_admin',
                    'Super', 'Admin', 1, 1
                )
            """, (password_hash,))
            
            print("Super admin account created. Username: admin, Password: admin123")
            
            # Commit changes
            connection.commit()
            print("Database initialization completed successfully")
            
    except Error as e:
        print(f"Error: {e}")
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()
            print("MySQL connection closed")

if __name__ == "__main__":
    create_database() 