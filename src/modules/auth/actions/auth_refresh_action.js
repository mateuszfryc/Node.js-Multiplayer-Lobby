import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

export const refreshAction = (database, envs) => async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      logger.warn('Refresh token missing');
      return jsonRes(res, 'Bad Request', [], 400);
    }
    const decodedUser = jwt.verify(refreshToken, envs.JWT_REFRESH_SECRET ?? '');
    if (!decodedUser) {
      logger.warn('Invalid refresh token');
      return jsonRes(res, 'Unauthorized', [], 401);
    }
    const user = await database.user.findUserById(decodedUser.id);
    if (!user) {
      logger.warn('User not found for refresh token');
      return jsonRes(res, 'Unauthorized', [], 401);
    }
    const match = await bcrypt.compare(refreshToken, user.refresh_token ?? '');
    if (!match) {
      logger.warn('Refresh token mismatch');
      return jsonRes(res, 'Unauthorized', [], 401);
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
    const data = { accessToken: newAccessToken, refreshToken: newRefreshToken };
    return jsonRes(res, '', data, 200);
  } catch (e) {
    logger.error('Error in /api_v1/refresh route', { error: e.message });
    return jsonRes(res, 'Server Error', [], 500);
  }
};
