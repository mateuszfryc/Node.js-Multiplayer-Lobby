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
    logger.debug('Decoded user role for logout', {
      role: requestingUser?.role,
    });
    if (!requestingUser) {
      logger.warn('Unauthorized');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    const user = await database.user.findUserById(requestingUser.id);
    if (!user) {
      logger.warn('User not found during logout');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    if (!user.logged_in || !user.refresh_token) {
      logger.warn('User already logged out');
      return jsonRes(res, '', 'Already logged out', [], 409);
    }
    await database.user.logoutUser(requestingUser.id);
    logger.info('User logged out successfully');
    return jsonRes(res, 'Logged out', '', {}, 200);
  } catch (error) {
    logger.error('Error in POST /api_v1/logout route', {
      error: error.message,
    });
    return jsonRes(res, '', 'Server error', [], 500);
  }
};
