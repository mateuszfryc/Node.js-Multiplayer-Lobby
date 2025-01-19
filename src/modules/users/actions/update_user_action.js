import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';
import { validatePlayerNameFormat } from '#utils/validators.js';
import dayjs from 'dayjs';

export const updateUserAction = (database) => async (req, res) => {
  logger.info('PATCH /api_v1/user/:user_id called', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const updateId = req.params.user_id;
    const { requestingUser } = req.body;

    if (!requestingUser) {
      logger.warn('Requesting user not found in request body');
      return jsonRes(res, 'Unauthorized', [], 401);
    }

    if (!requestingUser.id) {
      logger.warn('Unauthorized update request (no user id)');
      return jsonRes(res, 'Unauthorized', [], 401);
    }

    if (
      requestingUser.role !== 'admin' && // allow if request is made by admin
      requestingUser.id !== updateId // disallow updating other users
    ) {
      logger.warn(
        'Unauthorized update request (no user id or mismatched user id)'
      );
      return jsonRes(res, 'Unauthorized', [], 401);
    }

    const { player_name } = req.body;
    if (!player_name || !validatePlayerNameFormat(player_name)) {
      logger.warn('Invalid player_name in update request');
      return jsonRes(res, 'Invalid player_name', [], 400);
    }
    await database.user.updateUser(updateId, {
      player_name,
      updated_at: dayjs().toISOString(),
    });
    logger.info('User updated successfully');
    return jsonRes(res, '', [], 200);
  } catch (e) {
    logger.error('Error in PATCH /api_v1/user/:user_id route', {
      error: e.message,
    });
    return jsonRes(res, 'Server Error', [], 500);
  }
};
