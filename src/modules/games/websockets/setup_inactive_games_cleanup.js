import { logger } from '#config/logger.js';
import { GamesRepository } from '#games/persistence/games_repository.js';
import { gamesFeedEvents } from './setup_games_feed.js';

const checkGameResponsiveness = async (database, websockets, envs, game) => {
  const gameId = game.id;
  // @ts-expect-error false positive
  const lastHeartbeat = new Date(game.last_host_action_at) / 1000;
  const secondsDelta = Date.now() / 1000 - lastHeartbeat;
  const unreachableTime =
    envs.GAME_HEARTBEAT_INTERVAL * envs.NUMBER_OF_ALLOWED_SKIPPED_HEARTBEATS;

  if (
    game.status !== GamesRepository.STATUS_UNRESPONSIVE &&
    secondsDelta > unreachableTime
  ) {
    await database.game.setStatus(gameId, GamesRepository.STATUS_UNRESPONSIVE);
    websockets.emit(gamesFeedEvents.gameUnresponsive, { id: gameId });
    logger.warn('Game marked as unresponsive due to missing heartbeats', {
      id: gameId,
    });
    return;
  }
  //
  else if (secondsDelta > envs.INACTIVE_GAME_TIMEOUT + unreachableTime) {
    const game = await database.game.findById(gameId);
    if (!gameId) {
      logger.error('Game not found for deletion', { id: gameId });
      return;
    }
    const ownerId = game.owner_id;
    const owner = await database.user.findById(ownerId);
    if (!owner) {
      logger.error('Owner not found for game', { id: gameId, ownerId });
      return;
    }
    const hostedGames = (owner.hosted_games ?? []).filter(
      (id) => id !== gameId
    );
    await database.user.update(ownerId, { hosted_games: hostedGames });
    await database.game.delete(gameId);
    websockets.emit(gamesFeedEvents.gameDeleted, { id: gameId });
    logger.warn('Game deleted due to inactivity', { id: gameId });
    return;
  }
};

export const setupInactiveGamesCleanup =
  (database, websockets, envs) => async () => {
    try {
      // logger.debug('Checking active games heartbeat');
      const games = await database.game.findAll();
      if (!games || games.length === 0) {
        return;
      }
      for (const game of games) {
        await checkGameResponsiveness(database, websockets, envs, game);
      }
    } catch (err) {
      logger.error('Error during inactive games cleanup', { error: err });
    }
  };
