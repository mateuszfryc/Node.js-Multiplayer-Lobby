import { logger } from '#config/logger.js';

export const gamesFeedEvents = {
  gamesList: 'games_list',
  gameCreated: 'game_created',
  gameDeleted: 'game_deleted',
  gameUpdated: 'game_updated',
  gameUnresponsive: 'game_unresponsive',
  userJoined: 'user_joined',
  useLeft: 'user_left',
};

export const setupGamesFeed = (database) => async (socket) => {
  logger.info('WebSocket connected', { socketId: socket.id });

  socket.on('error', (err) => {
    logger.error('WebSocket error', { error: err });
  });
  const gamesList = await database.game.getCurrentGamesList();
  socket.on('subscribeToGamesList', () => {
    socket.emit(gamesFeedEvents.gamesList, gamesList);
  });
};
