import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';

export const deleteUserAction = (database) => async (req, res) => {
  logger.info('DELETE /api_v1/user/:user_id called', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const currentUser = req.body.requestingUser;
    logger.debug('Decoded user role for user deletion', {
      role: currentUser?.role,
    });
    if (!currentUser || currentUser.role !== 'admin') {
      logger.warn('Unauthorized user deletion attempt');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    const userId = req.params.user_id;
    const plainId = userId;
    if (!plainId) {
      logger.warn('Unable to decrypt user_id');
      return jsonRes(res, '', 'Invalid user_id', [], 400);
    }
    const user = await database.user.findUserById(userId);
    if (!user) {
      logger.warn('User not found for deletion');
      return jsonRes(res, '', 'Not found', [], 404);
    }
    await database.user.deleteUser(userId);
    logger.info('User deleted successfully');
    return jsonRes(res, '', 'Success', {}, 200);
  } catch (e) {
    logger.error('Error in DELETE /api_v1/user/:user_id route', {
      error: e.message,
    });
    return jsonRes(res, '', 'Server error', [], 500);
  }
};
