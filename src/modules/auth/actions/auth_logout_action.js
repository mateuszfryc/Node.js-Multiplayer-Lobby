import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';

export const logoutAction = (database) => async (req, res) => {
  logger.info('POST /api_v1/logout called', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const { requestingUser } = req.body;
    const user = await database.user.findUserById(requestingUser.id);
    if (!user) {
      logger.warn('User not found during logout');
      return jsonRes(res, 'Unauthorized', [], 401);
    }
    await database.user.logoutUser(requestingUser.id);
    logger.info('User logged out successfully');
    return jsonRes(res, '', [], 200);
  } catch (error) {
    logger.error('Error in POST /api_v1/logout route', {
      error: error.message,
    });
    return jsonRes(res, 'Server Error', [], 500);
  }
};
