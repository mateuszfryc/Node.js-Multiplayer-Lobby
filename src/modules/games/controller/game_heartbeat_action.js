import { logger } from '#config/logger.js';

export const gameHeartbeatAction =
  (database, activeGames) => async (req, res) => {
    const { game_id } = req.params;

    await database.game.refresh(game_id);
    const updatedGame = await database.game.findById(game_id);

    if (!updatedGame) {
      logger.error('Game not found for heartbeat', { game_id });
      return res.status(404).json({ error: 'Game not found' });
    }

    activeGames.set(game_id, updatedGame.toJSON());
    logger.info('Game heartbeat: ', { game_id });
    return res.status(200).json(updatedGame);
  };
