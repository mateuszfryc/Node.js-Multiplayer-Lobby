const http = require('http');
const express = require('express');
const { Server } = require('colyseus');
const { Room } = require('colyseus');

// Define a basic room handler
class MyRoom extends Room {
  onCreate(options) {
    console.log('Room created!');
  }

  onJoin(client, options) {
    console.log(client.sessionId, 'joined');
  }

  onLeave(client, consented) {
    console.log(client.sessionId, 'left');
  }

  onDispose() {
    console.log('Room disposed');
  }
}

const app = express();
const server = http.createServer(app);
const gameServer = new Server({
  server,
});

// Register the room
gameServer.define('my_room', MyRoom);

// Start listening for requests
const port = process.env.PORT || 3000;
server.listen(port, () => {
  console.log(`Listening on http://localhost:${port}`);
});
