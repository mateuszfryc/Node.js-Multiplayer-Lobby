Generate very small but scalable lobby server for multiplayer games in Node.js in single js file. Server is hosted on Heroku.

Implement functionalities:

1. Authenticate players and players with compheresive security measures.
2. Store players credentials and in game data (for now just user_name) in database, by default PostgreSQL, but can be switched to any other thanks to Database class.
3. Provide players with game CRUD operations via REST api.
4. Provide websocket feed of list of available games (players can connect to it in their game lobby and disconnect when leaving lobby).
5. Allow players to join and leave games, store connected player's IDs in game object and inform game's host and connected players when some one joins or leaves the game.

Implement security:

- HTTPS on all endpoints
- helmet package
- rate limiter on all endpoints
- JWT access and refresh tokens on all endpoints (if applicable)
- users data saved in database can only be USER_CHARS = A-Za-z0-9\!@#\$%\^&\*\_\+-\?\, filter out all other characters
- user_name must always be valid email, validated by sending confirmation email
- player_name must always have 3 - 16 chars and use only USER_CHARS
- if stored in database all IDs and tokens should be encrypted
- CORS is NOT impelemented, as this server is intended to be used by game clients only

Use:

- Express.js.
- PostgreSQL database.
- RESTful API for credentials (login/logout), updating user data, creating and deleting games.
- Websockets feed with games list to all players in the lobby.
- Database transactions to ensure data consistency
- Database JS class that will abstract away all database operations to allow easy database changes in the future

All that should be accomplished with existing packages if possible, avoid writing custom code.

All responses should use following JSON:
{
"message": "string", // empty if no message
"error": "string" // empty if no error
"data": "object" // empty array if no data
}

Database models:

User:
id: string
user_name: string // valid email
password: string // hashed
player_name: string
role: string // player, admin
logged_in: boolean
created_at: DateTime
updated_at: DateTime
validated_at: DateTime

Game:
id: string
ip: string
port: number
name: string
map_name: string
game_mode: string
connected_players: string[]
max_players: number
private: boolean
password: string
ping: number
created_at: DateTime
updated_at: DateTime

Activation:
user_id: string
token: string
created_at: DateTime
expires_at: DateTime

Tables:

- Users
- Games
- Activations

Flow:

Create new player account:

- POST: /api_v1/join
- payload data: user_name, password, player_name
- apply all valid security measures (JWT, HTTPS, helmet, rate limiter, etc.)
- permissions: admin only, check logged in user role
- check and return error if:
  - email as user_name is correctly formatted
  - email as user_name is already taken
  - user_name meets the requirements: min 3 chars, contains only USER_CHARS
  - password meets the requirements: min 8 chars, min 1 digit, min 1 small and high caps letter, min 1 of the special chars, contains only USER_CHARS
- create new user in database
- create new Activation object in database with token and expiration date
- send confirmation email to the user with link to confirm email address
- on success: created user object with it's id and return it back to the user

Confirm email address:

- url: /api_v1/confirm/:token
- payload: token
- check if user exists and if :token is valid (exists in data base by user id and didn't expired yet):
  - if valid, update the validated_at field and return "Account successfully validated" message
  - if not valid, return "Invalid token" message (do not specify if token is expired or not to the user)

Player will log in via game client with user name (always email) and password:

- POST: /api_v1/login
- payload data: user_name, password
- apply all valid security measures (JWT, HTTPS, helmet, rate limiter, etc.)
- validate improper characters from both user name and password with USER_CHARS
- validate improper user_name (email)
- check credentials against postgresql database
- check if users is already logged in (logged_in = true)
- return JWT token with timeout (default 24h)

Player will set user data visible to other players:

- PATCH: /api_v1/user
- payload: player_name = "" // this will expand in the future
- apply all valid security measures (JWT, HTTPS, helmet, rate limiter, etc.)
- error if:
  - player_name doesn't meet the requirements: min 3 chars, contains only USER_CHARS
- set player data in database for fields that are valid
- update: updated_at field
- return info on which fields where set and which where not

Player will open list of available servers (when openning the game lobby on the client app):

- GET: /api_v1/games
- payload: none
- apply all valid security measures (JWT, HTTPS, helmet, rate limiter, etc.)
- include user in websocket games feed (websocket connection)
- return list of available hosted games (empty list if no games created)

Player that Hosts the game will create new game:

- POST: /api_v1/games
- payload: ip, port, game_name, map_name, game_mode, max_players = 8, private = false, password = ""
- apply all valid security measures (JWT, HTTPS, helmet, rate limiter, etc.)
- check:
  - game_name against USER_CHARS
  - if the host already has other game (same ip and port) remove it from memory and from database and add info message that previous game was removed, user will be notified by the client app that creating a game means removing previous game, one game per user (for now)
- create new game object in memory and in database
- return created game object with it's id

Game host notifies of game state:

- PUT: /api_v1/games/:game_id
- payload: Game model
- apply all valid security measures (JWT, HTTPS, helmet, rate limiter, etc.)
- update the game both in memory and in database
- update: updated_at field
- send game state to all players in the game via websockets
- return updated game object with it's id to game owner and all other players in the game
- notes: game's host takes full responsibility for the game state updates: scores, players, map changes, game modes etc. that should be exchanged between host and connected players BUT: the data this server needs to have updated are that is relevant to the players in the lobby: connected_players, max_players, private, password, ping, game_mode, map_name, game_name, so it can be displayed to the players in the lobby.

Game host will delete the game:

- DELETE: /api_v1/games/:game_id
- payload: game_id
- apply all valid security measures (JWT, HTTPS, helmet, rate limiter, etc.)
- remove game object from memory and from database
- propagate this change to all players in the lobby via websockets

Player will log out:

- POST: /api_v1/logout
- payload: none
- apply all valid security measures (JWT, HTTPS, helmet, rate limiter, etc.)
- blacklist JWT in memory and in database, so it can't be used anymore
- update: user.logged_in = false, user.updated_at field
- remove JWT from memory and from database

Games list feed:

- this is a websocket connection that will send games states list to all players in the lobby (and lobby only)
- data included in the feed: game_name, map_name, game_mode, connected_players, max_players, private, password, ping

Logging:

- each action needs to be logged both to console and to file
