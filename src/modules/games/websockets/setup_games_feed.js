import { logger } from '#config/logger.js';

export const setupGamesFeed = (activeGames) => (socket) => {
  logger.info('WebSocket connected', { socketId: socket.id });
  socket.on('subscribeToGamesList', () => {
    socket.emit('games_list', Array.from(activeGames.values()));
  });
  socket.on('error', (err) => {
    logger.error('WebSocket error', { error: err });
  });
};
