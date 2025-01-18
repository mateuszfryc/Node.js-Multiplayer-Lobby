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
  logger.info('POST /api_v1/login called', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const { user_name, password } = req.body;
    if (!user_name || !password || !validateEmailFormat(user_name)) {
      logger.warn('Fields missing in login request');
      return jsonRes(res, '', 'Invalid credentials', [], 400);
    }
    if (!validateEmailFormat(user_name)) {
      logger.warn('Invalid email input during login');
      return jsonRes(res, '', 'Invalid credentials', [], 400);
    }
    const user = await database.user.findUserByName(user_name);
    if (!user) {
      logger.warn('Invalid credentials: user not found');
      return jsonRes(res, '', 'Invalid credentials', [], 401);
    }
    const passOk = await bcrypt.compare(password, user.password);
    if (!passOk) {
      logger.warn('Invalid credentials: wrong password');
      return jsonRes(res, '', 'Invalid credentials', [], 401);
    }
    if (!user.validated_at) {
      logger.warn('Email not validated for this user');
      return jsonRes(res, '', 'Email not validated', [], 403);
    }
    if (user.logged_in) {
      logger.warn('User already logged in');
      return jsonRes(res, '', 'Already logged in', [], 409);
    }
    const accessToken = jwt.sign(
      { id: user.id, role: user.role, player_name: user.player_name },
      envs.JWT_SECRET ?? '',
      { expiresIn: '15m' }
    );
    const refreshToken = jwt.sign(
      { id: user.id, role: user.role },
      envs.JWT_REFRESH_SECRET ?? '',
      { expiresIn: '7d' }
    );
    await database.user.loginUser(user, refreshToken);
    logger.info('User logged in successfully');
    return jsonRes(res, '', '', { accessToken, refreshToken }, 200);
  } catch (e) {
    logger.error('Error in /api_v1/login route', { error: e.message });
    return jsonRes(res, '', 'Server error', [], 500);
  }
};
