import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';

export const gameHeartbeatAction = (database) => async (req, res) => {
  const { game_id } = req.params;

  let updatedGame = await database.game.findById(game_id);
  if (!updatedGame) {
    logger.error('Game not found for heartbeat', { game_id });
    return res.status(404).json({ error: 'Game not found' });
  }

  await database.game.refresh(game_id);
  updatedGame = await database.game.findById(game_id);

  logger.info('Game heartbeat: ', { game_id });
  return jsonRes(res, '', [], 200);
};
