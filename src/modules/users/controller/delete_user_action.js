import { logger } from '#config/logger.js';
import { gamesFeedEvents } from '#games/websockets/setup_games_feed.js';
import { jsonRes } from '#utils/response.js';

export const deleteUserAction = (database, websockets) => async (req, res) => {
  const { requestingUser } = req.body;
  if (!requestingUser || requestingUser.role !== 'admin') {
    logger.warn('Unauthorized user deletion attempt');
    return jsonRes(res, 'Unauthorized', [], 401);
  }
  const userId = req.params.user_id;
  const plainId = userId;
  if (!plainId) {
    logger.warn('Unable to decrypt user_id');
    return jsonRes(res, 'Invalid user_id', [], 400);
  }
  const user = await database.user.findById(userId);
  if (!user) {
    logger.warn('User not found for deletion');
    return jsonRes(res, 'Not found', [], 404);
  }
  if (user.hosted_games && user.hosted_games.length) {
    for (const gId of user.hosted_games) {
      await database.game.delete(gId);
      websockets.emit(gamesFeedEvents.gameDeleted, { id: gId });
    }
  }
  await database.user.delete(userId);
  logger.info('User deleted successfully');
  return jsonRes(res, '', [], 200);
};
