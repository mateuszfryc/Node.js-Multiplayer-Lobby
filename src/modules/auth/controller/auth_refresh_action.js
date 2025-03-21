import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

export const refreshAction = (database, envs) => async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    logger.warn('Refresh authentication missing');
    return jsonRes(res, 'Bad Request', [], 400);
  }
  const decodedUser = jwt.verify(refreshToken, envs.JWT_REFRESH_SECRET ?? '');
  if (!decodedUser) {
    logger.warn('Invalid refresh authentication');
    return jsonRes(res, 'Unauthorized', [], 401);
  }
  const user = await database.user.findById(decodedUser.id);
  if (!user) {
    logger.warn('User not found for refresh authentication');
    return jsonRes(res, 'Unauthorized', [], 401);
  }
  const match = await bcrypt.compare(refreshToken, user.refresh_token ?? '');
  if (!match) {
    logger.warn('Refresh authentication mismatch');
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
  await database.user.login(user, newRefreshToken);
  logger.info('Authentication refreshed successfully');
  const data = { accessToken: newAccessToken, refreshToken: newRefreshToken };
  return jsonRes(res, '', data, 200);
};
