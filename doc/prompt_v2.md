Purpose:

- Create a lightweight Node.js lobby server for multiplayer games, deployable on Heroku.
- Use Express.js, PostgreSQL, RESTful APIs, and WebSockets.
- Provide strong security measures: HTTPS, helmet, rate limiting, JWT tokens, minimal allowed characters for inputs, and encryption for IDs/tokens.
- No CORS (intended for internal use by game clients only).

Server Requirements:

- Authenticate players with secure credentials handling.
- Store player credentials and in-game data (like user_name) in a PostgreSQL database (or another DB via a Database class abstraction).
- Offer CRUD operations for game objects through a REST API.
- Allow players to join/leave games, track connected player IDs, and notify the host and connected players of any join/leave events.

Security Measures:

- Force HTTPS on all endpoints.
- Use helmet for HTTP headers security.
- Apply rate limiting on all endpoints.
- Use JWT access and refresh tokens (where relevant).
- Ensure user data contains only USER\*CHARS = A-Za-z0-9!@#$%^&\*\*+-?, and filter out all other characters.
- Require user_name to be a valid email address (and confirm via email).
- Require player_name to have 3-16 characters from USER_CHARS only.
- Encrypt all IDs and tokens stored in the database with bcrypt and libsodium.
- Use environment variables for sensitive data such as API keys, encryption keys, or tokens for 3rd-party services and store in env.dev and env.prod files. Split them further to .db and .auth files. Use the following method (import it to the file):

```javascript
export const loadEnv = () => {
  let mode = null;
  if (process.env.NODE_ENV == 'production') {
    dotenv.config({ path: '.env.prod.db' });
    dotenv.config({ path: '.env.prod.auth' });
    mode = 'production';
  }
  if (process.env.NODE_ENV == 'development') {
    dotenv.config({ path: '.env.db' });
    dotenv.config({ path: '.env.auth' });
    mode = 'development';
  }
  if (mode === null) {
    throw new Error('Error: NODE_ENV not set');
  }

  const PORT = process.env.PORT ?? 3000;
  return { mode, PORT };
};
```

- Omit CORS usage.

Response Format (JSON only): { "message": "string", // empty if none "error": "string", // empty if none "data": {} // object or empty array }

Database Models:

User:

- id (string, encrypted)
- user_name (valid email, unique)
- password (hashed)
- player_name (valid by the above rules)
- role (player or admin)
- logged_in (boolean)
- created_at (DateTime)
- updated_at (DateTime)
- validated_at (DateTime or null)

Game:

- id (string, encrypted)
- ip (string)
- port (number)
- name (string, from USER_CHARS)
- map_name (string, from USER_CHARS)
- game_mode (string, from USER_CHARS)
- connected_players ([string])
- max_players (number)
- private (boolean)
- password (string, hashed if not empty)
- ping (number)
- created_at (DateTime)
- updated_at (DateTime)

Activation:

- user_id (string, encrypted)
- token (string, encrypted)
- created_at (DateTime)
- expires_at (DateTime)

Tables:

- Users
- Games
- Activations

Flow:

Create New Player Account (POST /api_v1/join):

- Payload: { user_name, password, player_name }
- Admin-only permission check (logged in user must have role=admin).
- Validate all fields:
  - user_name is a properly formatted email, allowed characters only, not already taken.
  - password has at least 8 chars, includes digits, uppercase, lowercase, special chars, and uses only USER_CHARS.
- Create the new user in the database, set logged_in=false by default.
- Create a matching Activation record (token + expiration).
- Send a confirmation email with a token link.

Confirm Email (GET /api_v1/confirm/:token):

- Retrieve the matching Activation record.
- Verify token is valid and not expired.
- If valid, set user.validated_at to now.
- If invalid, return a generic “Invalid token” message.

Login (POST /api_v1/login):

- Payload: { user_name, password }
- Validate fields (USER_CHARS only, user_name must be a valid email).
- Check credentials against the database.
- Check if user is already logged in (logged_in=true).
- On success, return a JWT token (valid for 24h by default).
- Set user.logged_in=true, user.updated_at to now.

Update User Data (PATCH /api_v1/user):

- Payload: { player_name }
- Validate player_name (3-16 chars, only USER_CHARS).
- Update player_name in database if valid.
- Set user.updated_at to now.
- Return success/failure details.

Retrieve Games List (GET /api_v1/games):

- No payload.
- Verify JWT and rate-limiting.
- Include the client in the WebSocket lobby feed for available games.
- Return the list of current games (empty if none).

Create a New Game (POST /api_v1/games):

- Payload: { ip, port, game_name, map_name, game_mode, max_players=8, private=false, password="" }
- Verify game_name and other fields match allowed characters.
- If the user already hosts a game with the same IP and port, remove that existing one from database - before creating the new game.
- Create the new game in memory and the database.
- Return the created game object.

Update Game State (PUT /api_v1/games/:game_id):

- Payload: updated Game model
- Restrict to the game host or admin.
- Update both in-memory and database game data.
- Set updated_at to now.
- Notify all connected players via WebSocket with the updated game state.
- Return the updated game object.

Delete a Game (DELETE /api_v1/games/:game_id):

- Payload: none
- Restrict to the game host or admin.
- Remove the game from memory and database.
- Notify all players in the lobby via WebSocket.

Logout (POST /api_v1/logout):

- Payload: none
- Verify JWT and mark it as invalid (blacklist in memory and database).
- Set user.logged_in=false, user.updated_at to now.
- Remove any tokens from memory and database.

Games List Feed (WebSocket):

- Provide a list of available games to any connected players in the lobby.
- Data includes: game_name, map_name, game_mode, connected_players, max_players, private, password, ing.
- Notify when a player joins or leaves a game.

Logging: Log all actions to console and to file. Rotate logs each day into backup file with date.

Code generation rules:

- Generate TypeScript code without line endings but with ";".
- Don't use comments in the code unless variable/method/class name can't reflect its purpose.
- Use async/await for all async operations.
- Use try/catch for error handling.
- Try to strike balance between minimalistic variables/methods/class names and readability.

Use provided:

- loadEnv function to load environment variables by importing it.
- response format for all API responses.
- database models and tables.
