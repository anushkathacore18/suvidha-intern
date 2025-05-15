import pymysql
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def create_database():
    # Get database configuration from environment variables
    DB_HOST = os.getenv('MYSQL_HOST', '0.0.0.0')
    DB_USER = os.getenv('MYSQL_USER', 'root')
    DB_PASSWORD = os.getenv('MYSQL_PASSWORD', 'Ombadade55555')
    DB_PORT = int(os.getenv('MYSQL_PORT', 3306))
    DB_NAME = 'internship_db'

    try:
        # Connect to MySQL server
        connection = pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            port=DB_PORT
        )
        
        with connection.cursor() as cursor:
            # Create database if it doesn't exist
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
            print(f"Database '{DB_NAME}' created or already exists")
            
            # Use the database
            cursor.execute(f"USE {DB_NAME}")
            
            # Create tables if needed (though SQLAlchemy will handle this)
            print("Database initialized successfully")
            
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise e
    finally:
        if 'connection' in locals():
            connection.close()

if __name__ == "__main__":
    create_database() 