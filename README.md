# Node.js Lobby for Multiplayer Games (with Authentication)

Node.js Lobby for Multiplayer Games (NLMG) is a simple and secure Node.js server designed to manage player authentication, creating and joining games as well as Websocket based games feed of currently hosted games. The server is **game-agnostic**, it can be integrated with any type of multiplayer game, providing a centralized hub for lobby management. It can be used as a base for more complex servers or as is if it fits game requirements.

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

- Real-time updates for hosted games status changes. Intended for players searching for games.
- Socket.IO integration for game feed updates.

## What NLMG doesn't do?

- **Matchmaking:** This server is not intended to be used for matchmaking. It is designed to be a lobby server where players can create and search games.
- **Join/Leave Management:** This server does not manage player joining or leaving games. It is up to the game host to manage this. There are optional REST endpoints for joining and leaving games, but they are not included in the intended flow.

## Intended Games Flow

**SERVER**:

- Requires authentication for all actions (REST or Websocket), except for account creation (if enabled by `ALLOW_USER_REGISTRATION`) and email confirmation.
- Handles requests to create new games, stores them in the database, and responds to the **HOST** with the game ID, data, and `GAME_HEARTBEAT_INTERVAL` value.
- Provides a real-time feed of active games to all connected **CLIENT**s.
- Marks a game as "unresponsive" and updates the game feed if the **HOST** misses heartbeat messages.
- Removes the "unresponsive" status if the **HOST** resumes sending heartbeat messages.
- Deletes the game if the **HOST** fails to send heartbeat messages before `INACTIVE_GAME_TIMEOUT` expires.
- Deletes games hosted by users upon their deletion.
- Allows multiple games per **CLIENT** based on `ALLOW_MULTIPLE_GAMES_PER_HOST`.
- Does not support reconnecting **CLIENT**s to the **HOST**.

**HOST**:

- Acts as both a player and a host.
- Sends a REST request to create a new game and receives the game ID, data, and `GAME_HEARTBEAT_INTERVAL`.
- Manages player join/leave independently but informs the **SERVER** of game state changes via REST.
- Manages the game lifecycle independently; the **SERVER** does not manage game progress.
- Sends a REST delete request to remove the game from the server.
- Sends periodic REST messages at intervals defined by `GAME_HEARTBEAT_INTERVAL` to keep the game active.
- Resumes sending heartbeat messages if missed, removing the "unresponsive" status.
- Informs the **SERVER** of game state changes via REST.
- Implements its own logic for kicking or banning players, as the **SERVER** does not handle this.

**CLIENT**:

- Connects to the Websocket feed to get a list of active games.
- Displays relevant game information, including "unresponsive" statuses.
- Sends a join request directly to the **HOST** and disconnects from the Websocket feed once a game is found.
- Can join "unresponsive" games and wait for the **HOST** or cancel the connection.
- Communicates with the **HOST** independently during the game.
- Reconnects to the Websocket feed to search for other games when the game ends or the client leaves.

---

## Setup Instructions

1. Clone the Repository: `git clone`;
2. `cd` into the project directory;
3. Create the following `.env` file in the project root:

```env
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
ALLOW_USER_REGISTRATION=false
GAME_HEARTBEAT_INTERVAL=10
NUMBER_OF_ALLOWED_SKIPPED_HEARTBEATS=3
INACTIVE_GAME_TIMEOUT=3600
ALLOW_MULTIPLE_GAMES_PER_HOST=false
```

4. Install dependencies: `npm install`;
5. Start the server:

```bash
# Development:
npm run dev
```

```bash
# Production:
npm run prod
```

## API Endpoints

### **Authentication**

| Method | Endpoint          | Description          |
| ------ | ----------------- | -------------------- |
| POST   | `/api_v1/login`   | Log in user          |
| POST   | `/api_v1/logout`  | Log out user         |
| POST   | `/api_v1/refresh` | Refresh access token |

### **User Management**

| Method | Endpoint                      | Description           |
| ------ | ----------------------------- | --------------------- |
| POST   | `/api_v1/users`               | Create a new user     |
| GET    | `/api_v1/users/verify/:token` | Confirm email address |
| GET    | `/api_v1/users/:user_id`      | Get user details      |
| PUT    | `/api_v1/users/:user_id`      | Update user details   |
| DELETE | `/api_v1/users/:user_id`      | Delete a user         |

### **Game Management**

| Method | Endpoint                          | Description           |
| ------ | --------------------------------- | --------------------- |
| GET    | `/api_v1/games`                   | Get list of all games |
| POST   | `/api_v1/games`                   | Create a new game     |
| PUT    | `/api_v1/games/:gameId/heartbeat` | Keep game alive       |
| PUT    | `/api_v1/games/:gameId`           | Update game details   |
| DELETE | `/api_v1/games/:gameId`           | Delete a game         |

Optinal endpoints, not included in the final flow:

| Method | Endpoint                      | Description  |
| ------ | ----------------------------- | ------------ |
| POST   | `/api_v1/games/:gameId/join`  | Join a game  |
| POST   | `/api_v1/games/:gameId/leave` | Leave a game |

---

## Testing

Manually test the server using tools like Postman. A Postman collection export file is available in the **doc** directory.

## Contributing

Contributions are welcome! Submit a pull request and allow me some time for review.

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
