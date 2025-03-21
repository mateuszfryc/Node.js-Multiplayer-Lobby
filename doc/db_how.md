Create a new database:
`sql
CREATE DATABASE your_database_name;
`

Connect to the newly created database:
`sql
\c your_database_name
`

Create a new user with a password:
`sql
CREATE USER your_username WITH PASSWORD 'your_password';
`

Grant all privileges on the database to the new user:
`sql
GRANT ALL PRIVILEGES ON DATABASE your_database_name TO your_username;
`

Grant all privileges on the public schema to the new user:
`sql
GRANT ALL ON SCHEMA public TO your_username;
`

Create a table named 'users':
`sql
CREATE TABLE users (id SERIAL PRIMARY KEY, display_name VARCHAR(20) NOT NULL, email VARCHAR(255) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL);
`

Insert a sample user into the 'users' table:
`sql
INSERT INTO users (display_name, email, password) VALUES ('display name', 'user@test.com', 'password');
`

Rename the 'uuid' column to 'id' in the 'users' table:
`sql
ALTER TABLE users RENAME COLUMN uuid TO id;
`

Add a primary key constraint to the 'id' column:
`sql
ALTER TABLE users ADD PRIMARY KEY (id);
`

Drop the 'id' column from the 'users' table:
`sql
ALTER TABLE users DROP COLUMN id;
`

Add a new 'uuid' column with a default value generated by gen_random_uuid():
`sql
ALTER TABLE users ADD COLUMN uuid UUID DEFAULT gen_random_uuid();
`

Choose database to work on:
`sql
\c your_database_name
`

Select all columns from the 'users' table:
`sql
SELECT * FROM users;
`

Display schema of the 'users' table:
`sql
\d users
`

Show tables in the database:
`sql
\dt
`

Drop all tables in the database:
`sql
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
GRANT ALL ON SCHEMA public TO your_username;
GRANT ALL ON SCHEMA public TO public;
`

Create admin user:
`sql
CREATE ROLE <username> WITH LOGIN PASSWORD 'password';
ALTER ROLE <username> WITH SUPERUSER;
`

Delete user from users:
`sql
DELETE FROM users WHERE user_name = 'user@mail.com';
`

Logout user:
`sql
UPDATE users SET refresh_token = NULL, updated_at = NOW() WHERE user_name = 'user@mail.com';
`
