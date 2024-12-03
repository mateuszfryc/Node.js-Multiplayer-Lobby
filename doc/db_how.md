```psql
CREATE DATABASE your_database_name;
\c your_database_name
CREATE USER your_username WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE your_database_name TO your_username;
GRANT ALL ON SCHEMA public TO your_username;

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  display_name VARCHAR(20) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL
);

INSERT INTO users (display_name, email, password) VALUES ('display name', 'user@test.com', 'password');
```
