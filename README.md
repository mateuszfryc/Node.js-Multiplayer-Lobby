# Game Agnostic Lobby Server (GALS)

Game Agnostic Lobby Server (GALS) is a simple and secure Node.js server designed to manage player authentication, creating and joining games as well as Websocket based games feed of currently hosted games. The server is **game-agnostic**, it can be integrated with any type of multiplayer game, providing a centralized hub for lobby management. It can be used as a base for more complex servers or as is if it fits Your requirements.

## Features

**Authentication:**

- Email/password-based user registration and login.
- JWT-based access and refresh tokens.
- Role-based access control (admin/player).
- Email validation with token-based confirmation.

**Game Management:**

- Create, update, delete, and manage games.
- In-memory active game tracking with database synchronization.

**Security:**

- Passwords hashed with bcrypt.
- Helmet.js for HTTP headers security.
- Rate limiting and speed limiting for requests.
- CSP (Content Security Policy) enforcement.

**Scalability:**

- Modular architecture for easy feature extensions.
- Socket.IO integration for real-time updates.

**Custom Logging:**

- Winston-based logging with daily file rotation and sensitive data redaction.

**Websockets Games Feed**

- Real-time updates for hosted games status changes. Intended for player searching for games.
- Socket.IO integration for game feed updates.

## What GALS doesn't do?

- **Matchmaking:** This server is not intended to be used for matchmaking. It is designed to be a lobby server where players can create and search games.
- **Join/Leave Management:** This server does not manage player joining or leaving games. It is up to the game host to manage this.

## Intended games flow

- All of the below actions (REST or Websocket) require verified user account and authentication (login).
- Host is also a player (client).
- GALS doesn't dictate if the user account can by created by user or not. Server owner can decide to switch ALLOW_USER_REGISTRATION environment variable on/off to allow/disallow user registration wihtout admin role.

**HOST**:

- Creates new game.
- Makes REST request to the server to create new game.
- Receives response from server with new game id, its data, GAME_INACTIVE_INTERVAL and GAME_INACTIVE_TIMEOUT values.
- Is now ready to receive **direct** join requests from other clients.
- Manages game lifecycle on its own - the **SERVER** doesn't care about the course of the game.
- Manages joining and leaving players independently from the **SERVER** BUT should inform the **SERVER** about the game state changes.
- Sends REST delete request to the **SERVER** when the host decides to.
- Sends periodic Websocket messages in short intervals defined by GAME_INACTIVE_INTERVAL (in seconds) to the server to keep the game alive on the **SERVER**.
- If the **HOST** will skip the hartbeat due to crash or any internal issues it should resume sending the periodic heartbeat messages to the server to keep the game alive on the **SERVER**. If it does the game "unresponsive" status will be removed from that game.
- **HOST** can (but doesn't have to) save the last heartbeat response time and compere that to the GAME_INACTIVE_TIMEOUT value to decide if it should stop sending the heartbeat messages and delete the game.
- Provides (or not) clients with the reconnect functionality.
- Stays connected to Websocket feed to be able to quickly inform players in the lobby about game changes.
- If the host must be able to kick or ban players from that game it must implement it's own logic to handle that and disallow those player form joining the game upon their direct join attempt. The game for kicked/banned **CLIENT**s will be still visible in the Websocket feed.

**SERVER**:

- Receives request to create new game.
- Creates new game in database.
- Sends response to **HOST** with new game id, its data and GAME_INACTIVE_INTERVAL.
- Sends game feed update to all clients connected to Websocket feed with new game data.
- Whenever receives game udpate from **HOST**s propagates that update to all clients connected to Websocket feed.
- If the **HOST** doesn't send periodic heartbeat messages for the game, the **SERVER** will set it's status to "unresponsive" and send game feed update to all clients connected to Websocket feed.
- If the **HOST** will resume sending the periodic heartbeat messages to the server the game "unresponsive" status will be removed from that game and the game feed update will be sent to all clients connected to Websocket feed.
- If the **HOST** won't resume sending the periodic heartbeat messages to the server before the GAME_INACTIVE_TIMEOUT runes out the game will be deleted and the game feed update will be sent to all clients connected to Websocket feed. Event if the **HOST** manages to send the heartbeat message after the game deletion the game will not be restored and any attempts to change or delete the game will be rejected as 404 - not found/bad request.
- In the unlikely scenerio where user being deleted has any games hosted the server will delete those games and send game feed update to all clients connected to Websocket feed.
- Based on MULTIPLE_GAMES_PER_HOST value **SERVER** can allow/disallow **HOST**s to host multiple games at once. It should depend on game's multiple factors.

**CLIENT**:

- Connects to a Websocket feed to get list of currently hosted games
- Decides which information to display in the client's game lobby, including "unresponsive" games status
- Once game is found, sends direct join request to that game's **HOST** AND **leaves the Websocket feed** (to save resources)
- Since join and leave action happens between **HOST** and the **CLIENT** the latter can decide to joint the game with "unresponsive" status and wait for the **HOST** connection or not. Implementing "cancel connection" functionality is up to the **CLIENT**.
- Through the entire game communicates with **HOST** independently from the **SERVER**
- When the game is over or client decides to leave, it can connect to the Websocket feed again to search for other games

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
GAME_INACTIVE_INTERVAL=30 (seconds)
GAME_INACTIVE_TIMEOUT=120 (seconds)
MULTIPLE_GAMES_PER_HOST=false
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
| POST   | `/api_v1/games/:gameId/join`  | Delete a game         |
| POST   | `/api_v1/games/:gameId/leave` | Delete a game         |

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
