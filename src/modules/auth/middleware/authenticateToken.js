import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';
import jwt from 'jsonwebtoken';

export const authenticateToken = (database) => async (req, res, next) => {
  logger.info('Authenticating token for incoming request', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });

  const authHeader = req.headers.authorization;
  if (!authHeader) {
    logger.warn('No Authorization header found');
    return jsonRes(res, 'Unauthorized', [], 401);
  }

  const accessToken = authHeader?.split(' ')[1];
  if (!accessToken) {
    logger.warn('No access token found in Authorization header');
    return jsonRes(res, 'Unauthorized', [], 401);
  }
  try {
    const decodedUser = jwt.verify(accessToken, process.env.JWT_SECRET ?? '');

    // this check is very important to avoid passing valid tokens with invalid id
    const user = await database.user.findById(decodedUser.id);
    if (!user) {
      logger.warn('User not found in database', { userId: decodedUser.id });
      return jsonRes(res, 'Unauthorized', [], 401);
    }
    logger.debug('Token decoded successfully', { role: decodedUser.role });
    req.body.requestingUser = decodedUser;
    next();
  } catch (e) {
    if (e.name === 'TokenExpiredError') {
      logger.info('Token expired', { error: e.message });
    } //
    else {
      logger.error('Failed to authenticate token', { error: e.message });
    }
    return jsonRes(res, 'Unauthorized', [], 401);
  }
};
