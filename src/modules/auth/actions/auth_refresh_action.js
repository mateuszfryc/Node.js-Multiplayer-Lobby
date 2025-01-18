import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

export const refreshAction = (database, envs) => async (req, res) => {
  logger.info('POST /api_v1/refresh called', {
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
    const { refreshToken } = req.body;
    if (!refreshToken) {
      logger.warn('Refresh token missing');
      return jsonRes(res, '', 'Refresh token missing', [], 400);
    }
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, envs.JWT_REFRESH_SECRET ?? '');
    } catch (e) {
      logger.warn('Invalid refresh token');
      // Log the user out by clearing the refresh token in the database
      await database.user.logoutUser(req.user.id);
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    logger.debug('Refresh token decoded successfully', {
      role: decoded?.role,
    });
    const user = await database.user.findUserById(decoded.id);
    if (!user) {
      logger.warn('User not found for refresh token');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    const match = await bcrypt.compare(refreshToken, user.refresh_token ?? '');
    if (!match) {
      logger.warn('Refresh token mismatch');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    const newAccessToken = jwt.sign(
      { id: user.id, role: user.role, player_name: user.player_name },
      envs.JWT_SECRET ?? '',
      { expiresIn: '15m' }
    );
    const newRefreshToken = jwt.sign(
      { id: user.id, role: user.role },
      envs.JWT_REFRESH_SECRET ?? '',
      { expiresIn: '7d' }
    );
    await database.user.loginUser(user, newRefreshToken);
    logger.info('Token refreshed successfully');
    return jsonRes(
      res,
      'Token refreshed',
      '',
      { accessToken: newAccessToken, refreshToken: newRefreshToken },
      200
    );
  } catch (e) {
    logger.error('Error in /api_v1/refresh route', { error: e.message });
    return jsonRes(res, '', 'Unauthorized', [], 401);
  }
};
