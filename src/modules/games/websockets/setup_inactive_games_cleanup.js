import { logger } from '#config/logger.js';
import { GamesRepository } from '#games/persistence/games_repository.js';

const checkGameResponsiveness = async (
  database,
  websockets,
  activeGames,
  envs,
  gameId,
  game
) => {
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
    activeGames.set(gameId, {
      ...game,
      status: GamesRepository.STATUS_UNRESPONSIVE,
    });
    websockets.emit('game_unresponsive', { id: gameId });
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
    activeGames.delete(gameId);
    websockets.emit('game_deleted', { id: gameId });
    logger.warn('Game deleted due to inactivity', { id: gameId });
    return;
  }
};

export const setupInactiveGamesCleanup =
  (database, websockets, activeGames, envs) => async () => {
    // logger.debug('Checking active games heartbeat');
    for (const [id, game] of activeGames.entries()) {
      await checkGameResponsiveness(
        database,
        websockets,
        activeGames,
        envs,
        id,
        game
      );
    }
  };
