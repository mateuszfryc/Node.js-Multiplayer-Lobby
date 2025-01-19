import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';

export const logoutAction = (database) => async (req, res) => {
  const { requestingUser } = req.body;
  const user = await database.user.findUserById(requestingUser.id);
  if (!user) {
    logger.warn('User not found during logout');
    return jsonRes(res, 'Unauthorized', [], 401);
  }
  await database.user.logoutUser(requestingUser.id);
  logger.info('User logged out successfully');
  return jsonRes(res, '', [], 200);
};
