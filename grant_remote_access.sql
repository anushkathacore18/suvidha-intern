-- Create user with remote access
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY 'Ombadade55555';

-- Grant all privileges to the user for remote access
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;

-- Create the database if it doesn't exist
CREATE DATABASE IF NOT EXISTS internship_db;

-- Flush privileges to apply changes
FLUSH PRIVILEGES; 

