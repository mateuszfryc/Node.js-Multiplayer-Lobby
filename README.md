# Game Agnostic Lobby Server (GALS)

Game Agnostic Lobby Server (GALS) is a simple but for the most of the part secure Node.js server designed to manage player authentication, matchmaking, and game sessions. The server is **game-agnostic**, meaning it can be integrated with any type of multiplayer game, providing a centralized hub for lobby management. It can be used as a base for more complex servers or as is if it fits Your requirements.

## Why single file structure?

1. The server was suppose to be made quick without adding unnecessary complexity or abstractions but still somwhat scalable.

2. This was the first time I was making this kind of server and didn't knew what to expect. Single file allows for lightning fast overwiew of the whole project, which isn't as simple as with modular file system approach.

3. Additionally single file enables faster development and iteration with AI tools in environments like VS Code. This approach minimizes context switching and simplifies changes, allowing for rapid prototyping and testing.

4. As the project will (hopefully) grow, I will be able to refactor it into more modular file structure, but for now it's a good starting point.

---

## Features

- **Authentication:**

  - Email/password-based user registration and login.
  - JWT-based access and refresh tokens.
  - Role-based access control (admin/player).
  - Email validation with token-based confirmation.

- **Game Management:**

  - Create, update, delete, and manage games.
  - Player join/leave game functionality.
  - In-memory active game tracking with database synchronization.

- **Security:**

  - Passwords hashed with bcrypt.
  - Helmet.js for HTTP headers security.
  - Rate limiting and speed limiting for requests.
  - CSP (Content Security Policy) enforcement.

- **Scalability:**

  - Modular architecture for easy feature extensions.
  - Socket.IO integration for real-time updates.

- **Custom Logging:**
  - Winston-based logging with daily file rotation and sensitive data redaction.

---

## Prerequisites

Ensure you have the following installed:

- **Node.js** (v16.x or later)
- **npm** (v8.x or later)
- **PostgreSQL** (v12.x or later)

---

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/game-agnostic-lobby-server.git
cd game-agnostic-lobby-server
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment Variables

Create the following `.env` files in the project root (or use `.env.db`, `.env.auth`, and `.env.prod.*` as needed):

#### `.env` Example:

```env
NODE_ENV=development
PORT=3000
JWT_SECRET=your_jwt_secret
JWT_REFRESH_SECRET=your_refresh_secret
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=your_db_name
DB_HOST=localhost
DB_PORT=5432
DB_FORCE_SYNC=false
SSL_KEY_PATH=./path/to/ssl.key
SSL_CERT_PATH=./path/to/ssl.crt
USE_SSL=true
SMTP_HOST=smtp.example.com
SMTP_USER=smtp_user
SMTP_PASS=smtp_password
SMTP_PORT=587
FROM_EMAIL=no-reply@example.com
ADMIN_USER_NAME=admin@example.com
ADMIN_PASSWORD=AdminPass123!
ADMIN_PLAYER_NAME=AdminPlayer
```

### 4. Start the Server

#### Development Mode:

```bash
npm run dev
```

#### Production Mode:

```bash
NODE_ENV=production npm start
```

---

## API Endpoints

### **Authentication**

| Method | Endpoint          | Description          |
| ------ | ----------------- | -------------------- |
| POST   | `/api_v1/login`   | Log in user          |
| POST   | `/api_v1/logout`  | Log out user         |
| POST   | `/api_v1/refresh` | Refresh access token |

### **User Management**

| Method | Endpoint                 | Description           |
| ------ | ------------------------ | --------------------- |
| POST   | `/api_v1/user`           | Create a new user     |
| PATCH  | `/api_v1/user`           | Update user details   |
| DELETE | `/api_v1/user/:userId`   | Delete a user         |
| GET    | `/api_v1/confirm/:token` | Confirm email address |

### **Game Management**

| Method | Endpoint                      | Description           |
| ------ | ----------------------------- | --------------------- |
| GET    | `/api_v1/games`               | Get list of all games |
| POST   | `/api_v1/games`               | Create a new game     |
| PUT    | `/api_v1/games/:gameId`       | Update game details   |
| DELETE | `/api_v1/games/:gameId`       | Delete a game         |
| POST   | `/api_v1/games/:gameId/join`  | Join a game           |
| POST   | `/api_v1/games/:gameId/leave` | Leave a game          |

---

## Testing

Server simplicity allows to manually test it with tools like Postman, which is the approach I took. Look into **doc** directory for postman collection export file.

## Contributing

Contributions are welcome! I am by no means senior backend developer, I do hope this will be refined over time with Your help. Submit a pull request and give me some time to respond.

---

## License

This project is licensed under the [GNU Affero General Public License v3.0](https://www.gnu.org/licenses/agpl-3.0.html).

Copyright (c) 2025 Mateusz Fryc. All rights reserved.

---

## Acknowledgments

- **Express.js** for server framework.
- **Socket.IO** for real-time updates.
- **Sequelize** for database ORM.
- **bcrypt** for secure password hashing.
- **Helmet.js** for enhanced security.
- **Winston** for logging.
- **OpenAI** for providing incredible tools.
- And all other amazing open-source libraries used in this project!
