import { logger } from '#config/logger.js';

export const setupGamesFeed = (database, activeGames) => (socket) => {
  logger.info('WebSocket connected', { socketId: socket.id });

  socket.on('error', (err) => {
    logger.error('WebSocket error', { error: err });
  });

  socket.on('subscribeToGamesList', () => {
    socket.emit('games_list', Array.from(activeGames.values()));
  });
};
