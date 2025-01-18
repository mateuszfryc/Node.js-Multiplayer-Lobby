import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';
import jwt from 'jsonwebtoken';

export async function authenticateToken(req, res, next) {
  logger.info('Authenticating token for incoming request', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      logger.warn('No Authorization header found');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    const accessToken = authHeader.split(' ')[1];
    if (!accessToken) {
      logger.warn('No access token found in Authorization header');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET ?? '');
    logger.debug('Token decoded successfully', { role: decoded.role });
    req.body.requestingUser = decoded;
    next();
  } catch (e) {
    logger.error('Failed to authenticate token', { error: e.message });
    return jsonRes(res, '', 'Unauthorized', [], 401);
  }
}
