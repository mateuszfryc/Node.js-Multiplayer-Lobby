const http = require('http');
const express = require('express');
const { Server } = require('colyseus');
const { Room } = require('colyseus');

// Define a basic room handler
class CustomRoom extends Room {
  onMessage(client, message) {
    console.log('Message received from', client.sessionId, ':', message);

    if (message.action === 'join') {
      console.log(client.sessionId, 'is attempting to join.');
      // Handle other game logic here for joining.
    }
  }

  onCreate(options) {
    console.log('Room created!');
    this.setSeatReservationTime(10000);
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
gameServer.define('custom_room', CustomRoom);

// Start listening for requests
const port = process.env.PORT || 3000;
server.listen(port, () => {
  console.log(`Listening on http://localhost:${port}`);
});
