import { logger } from '#config/logger.js';
import jwt from 'jsonwebtoken';

export const websocketsJwtAuth = (envs) => (socket, next) => {
  try {
    const token =
      socket.handshake.auth?.token ??
      socket.handshake.headers?.authorization?.split(' ')[1];
    if (!token) {
      throw new Error('Missing token');
    }
    const decoded = jwt.verify(token, envs.JWT_SECRET);
    socket.requestingUser = decoded;
    return next();
  } catch (err) {
    logger.error('WebSocket auth error', { error: err.message });
    return next(err);
  }
};
