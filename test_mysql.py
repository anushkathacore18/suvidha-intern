import mysql.connector
from mysql.connector import Error
import pymysql
from dotenv import load_dotenv
import os
import socket

# Load environment variables
load_dotenv()

def is_port_open(host, port):
    """Check if a port is open on the host"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def try_connection(library, host, user, password):
    print(f"Trying connection with {library} - User: {user}, Password: {password}")
    try:
        if library == "connector":
            connection = mysql.connector.connect(
                host=host,
                user=user,
                password=password,
                connect_timeout=5
            )
            if connection.is_connected():
                print(f"SUCCESS with mysql.connector using password: {password}")
                connection.close()
                return True
        elif library == "pymysql":
            connection = pymysql.connect(
                host=host,
                user=user,
                password=password,
                connect_timeout=5
            )
            print(f"SUCCESS with pymysql using password: {password}")
            connection.close()
            return True
    except Exception as e:
        print(f"Failed: {e}")
    return False

def test_mysql_connection():
    # Check if port 3306 is open
    print("\nChecking if MySQL port is open...")
    if is_port_open('localhost', 3306):
        print("Port 3306 is OPEN on localhost")
    elif is_port_open('127.0.0.1', 3306):
        print("Port 3306 is OPEN on 127.0.0.1")
    else:
        print("MySQL port 3306 is CLOSED")
        
    # Try different password variations
    passwords = [
        "Ombadade55555",   # Original password
        "OmBadade55555",   # Different capitalization
        "",                # Empty password
        "ombadade55555",   # All lowercase
        "OMBADADE55555"    # All uppercase
    ]
    
    hosts = ["localhost", "127.0.0.1"]
    libraries = ["connector", "pymysql"]
    
    success = False
    
    print("\nTrying various connection combinations...")
    for library in libraries:
        for host in hosts:
            for password in passwords:
                if try_connection(library, host, "root", password):
                    print(f"\nSUCCESS! The correct password is: {password}")
                    print(f"Host: {host}, Library: {library}")
                    
                    # Update .env with working credentials
                    success = True
                    break
            if success:
                break
        if success:
            break
    
    if not success:
        print("\nAll connection attempts failed. Please try:")
        print("1. Reset your MySQL root password")
        print("2. Check if MySQL is configured to accept remote connections")
        print("3. Use MySQL Workbench to test your credentials directly")

if __name__ == "__main__":
    test_mysql_connection() 