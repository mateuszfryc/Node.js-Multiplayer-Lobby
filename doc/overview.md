On Heroku we host very small server in Node.js that needs to connect testers to test multiplayer game made with Unreal Engine in Listen Server mode.

The server will be responsible for:

1. Authenticate players and players (with all security measures)
2. Store their data in database (PostgreSQL)
3. Provide list of available games and allow players to create new game or join existing one

Security:

- HTTPS
- CORS protection (if applicable to this type of server)
- helmet package
- rate limiter on all endpoints
- JWT access and refresh tokens
- user can use only USER_CHARS
- user_name must always be valid email
- player_name must always have 3 - 16 chars and use only USER_CHARS
- if stored in database all IDs and tokens should be encrypted

Functionality:

- based on Express.js and websockets
- PostgreSQL database to store user and game data
- websockets to send game state changes to all players in the game
- database transactions to ensure data consistency
- Database js class that will abstract away all database operations to allow easy database changes in the future

All that should be accomplished with existing packages if possible, to avoid writing custom code.

All responses should use following JSON:
{
"message": "string", // empty if no message
"error": "string" // empty if no error
}

Models:

User:
id: string
user_name: string
password: string // hashed
player_name: string
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

GameFeed:
id: string
name: string
players: number
max_players: number
private: boolean
ping: number

Activation:
user_id: string
token: string
created_at: DateTime
expires_at: DateTime

Tables:

- User
- Game
- Activation

Flow:

1. Player will log in via game client with user name (always email) and password:

- POST: /api_v1/login
- payload: user_name, password
- validate improper characters from both user name and password with USER_CHARS
- validate improper user_name (email)
- check credentials against postgresql database
- check if users is already logged in (logged_in = true)
- return JWT token with timeout (default 24h)

2. Player will set user data visible to other players:

- PATCH: /api_v1/user
- payload: player_name = "" // this will expand in the future
- use JWT to authenticate
- check:
  - validate improper characters from player_name
- set player data in database for fields that are valid
- update: updated_at field
- return info on which fields where set and which where not

3. Player will open list of available servers:

- GET: /api_v1/games
- payload: none
- use JWT to authenticate
- include user in websocket games feed (websocket connection)
- return list of available servers (games) with their data: Game model
- return empty list if no servers are available

4. Player that Hosts the game will create new game:

- POST: /api_v1/games
- payload: ip, port, name, map_name, game_mode, max_players = 8, private = false, password = ""
- use JWT to authenticate
- check:
  - name against USER_CHARS
  - if this game: ip, port and name already exists do not create new game, send message: "Game already exists"
  - if the host already has other game (same ip and port) remove it from memory and from database and add info message that previous game was removed, user will be notified by the client app that creating a game means removing previous game, one game per user (for now)
- create new game object in memory in database
- return created game object with it's id

5. Game host notifies of game state:

- PUT: /api_v1/games/:game_id
- payload: Game model
- use JWT to authenticate
- update the game both in memory and in database
- update: updated_at field
- send game state to all players in the game via websockets
- return updated game object with it's id to game owner and all other players in the game

This should account for all game changes. The idea is the host manages clients, map changes, informs connected clients about new clients (join and leave), game end, etc. Clients connect directly to the host and disconnect with it. The host will be responsible for all game state changes, that should be send to all players in the game AND lobby. Host should also notify of the game changes quite often, if possible.

7. Game host will delete the game:

- DELETE: /api_v1/games/:game_id
- payload: game_id
- use JWT to authenticate
- remove game object from memory and from database
- propagate this change to all players in the game

8. Player will log out:

- POST: /api_v1/logout
- payload: none
- use JWT to authenticate
- blacklist JWT in memory and in database, so it can't be used anymore
- update: logged_in = false, updated_at field
- remove JWT from memory and from database

For now no player can create their own accounts, that's done by admin via:

- POST: /api_v1/join
- payload: user_name, password, player_name, player_image
- use JWT to authenticate
- check and return error if:
  - email is correctly formatted
  - email is already taken
  - user name is already taken
  - user name meets the requirements: min 3 chars, contains only: A-Za-z\!@#\$%\^&\*\_\+-\?
  - password meets the requirements: min 8 chars, min 1 digit, min 1 small and high caps letter, min 1 of the special chars, contains only: A-Za-z\!@#\$%\^&\*\_\+-\?
- create new user in database
- create new Activation object in database with token and expiration date
- send confirmation email to the user with link to confirm email address
- return created user object with it's id

Confirmation request PUT:

- url: /api_v1/confirm/:token
- payload: token
- check if user exists and if :token is valid (exists in data base by user id and didn't expired yet):
  - if valid, update the validated_at field and return "Account successfully validated" message
  - if not valid, return "Invalid token" message (do not specify if token is expired or not to the user)

Games list feed:

- this is a websocket connection that will send games states list to all players in the lobby (and lobby only)
- this will use short version of Game model: GameFeed

Logging:

- each action needs to be logged
