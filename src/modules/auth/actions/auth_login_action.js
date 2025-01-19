import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';
import { validateEmailFormat } from '#utils/validators.js';
import bcrypt from 'bcrypt';
import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';
import jwt from 'jsonwebtoken';

export const loginLimiter = rateLimit({
  windowMs: 60000,
  max: 5,
  message: { error: 'Too many login attempts. Please try again later.' },
});
export const loginSpeedLimiter = slowDown({
  windowMs: 60000,
  delayAfter: 5,
  delayMs: () => 1000,
  maxDelayMs: 10000,
});

export const loginAction = (database, envs) => async (req, res) => {
  const { user_name, password } = req.body;
  if (!user_name) {
    logger.warn('No user_name in login request');
    return jsonRes(res, 'Invalid credentials', [], 400);
  }
  if (!password) {
    logger.warn('No password in login request');
    return jsonRes(res, 'Invalid credentials', [], 400);
  }
  if (!validateEmailFormat(user_name)) {
    logger.warn('Invalid email format in login request');
    return jsonRes(res, 'Invalid credentials', [], 400);
  }
  const user = await database.user.findUserByName(user_name);
  if (!user) {
    logger.warn('User not found in database');
    return jsonRes(res, 'Invalid credentials', [], 401);
  }
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    logger.warn('Password mismatch');
    return jsonRes(res, 'Invalid credentials', [], 401);
  }
  if (!user.validated_at) {
    logger.warn('Email not validated');
    return jsonRes(res, 'Email not validated', [], 403);
  }
  const accessToken = jwt.sign(
    { id: user.id, role: user.role, player_name: user.player_name },
    envs.JWT_SECRET ?? '',
    { expiresIn: '15m' }
  );
  const refreshToken = jwt.sign(
    { id: user.id, role: user.role },
    envs.JWT_REFRESH_SECRET ?? '',
    { expiresIn: '1d' }
  );
  await database.user.loginUser(user, refreshToken);
  logger.info('User logged in successfully');
  const data = { accessToken, refreshToken };
  return jsonRes(res, '', data, 200);
};
