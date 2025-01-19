import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';

export const getUserAction = (database) => async (req, res) => {
  const { requestingUser } = req.body;
  const { user_id } = req.params;

  if (!requestingUser) {
    logger.warn('Unauthorized user request attempt');
    return jsonRes(res, 'Unauthorized', [], 401);
  }

  if (requestingUser.role !== 'admin' && requestingUser.id !== user_id) {
    logger.warn('Unauthorized user request attempt (mismatched user id)');
    return jsonRes(res, 'Unauthorized', [], 401);
  }

  if (!user_id) {
    logger.warn('User id missing in request');
    return jsonRes(res, 'Bad Request', [], 400);
  }

  const user = await database.user.findUserById(user_id);
  if (!user) {
    logger.warn('User not found for user_id', { user_id });
    return jsonRes(res, 'Bad Request', [], 404);
  }

  logger.info('User found successfully', { user_id });
  const data = {
    id: user.id,
    player_name: user.player_name,
  };
  return jsonRes(res, '', data, 200);
};
