import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';
import {
  validateEmailFormat,
  validatePasswordFormat,
  validatePlayerNameFormat,
} from '#utils/validators.js';
import dayjs from 'dayjs';
import { v4 as uuidv4 } from 'uuid';

export const createUserAction =
  (database, envs, mailer) => async (req, res) => {
    logger.info('POST /api_v1/user called', {
      method: req.method,
      url: req.url,
      clientIp: req.ip,
    });
    try {
      const user = req.body.requestingUser;
      logger.debug('Decoded user role for register route', {
        role: user?.role,
      });
      const { user_name, password, player_name } = req.body;
      if (!user || user.role !== 'admin') {
        logger.warn('Non-admin attempted to create new user');
        return jsonRes(res, 'Request failed', [], 400);
      }
      if (!user_name || !password || !player_name) {
        logger.warn('Missing fields in /api_v1/register');
        return jsonRes(res, 'Request failed', [], 400);
      }
      if (!validateEmailFormat(user_name)) {
        logger.warn('Invalid email format in /api_v1/register');
        return jsonRes(res, 'Request failed', [], 400);
      }
      if (!validatePasswordFormat(password)) {
        logger.warn('Invalid password format in /api_v1/register');
        return jsonRes(res, 'Request failed', [], 400);
      }
      if (!validatePlayerNameFormat(player_name)) {
        logger.warn('Invalid player_name format in /api_v1/register');
        return jsonRes(res, 'Request failed', [], 400);
      }
      const existing = await database.user.findUserByName(user_name);
      if (existing) {
        logger.warn('Attempt to create existing user');
        return jsonRes(res, 'Request failed', [], 400);
      }
      const now = dayjs().toISOString();
      const newUser = await database.user.create(
        user_name,
        password,
        player_name,
        'player'
      );
      logger.info('New user created successfully');
      const token = uuidv4();
      const exp = dayjs().add(1, 'day').toISOString();
      await database.activation.createActivation({
        user_id: newUser.id,
        token,
        created_at: now,
        expires_at: exp,
      });
      logger.debug('Activation token created for new user (token redacted)');
      try {
        const verificationLink = `${envs.USE_SSL ? 'https' : 'http'}://${
          req.headers.host
        }/api_v1/users/verify/${token}`;
        await mailer.sendMail({
          from: envs.FROM_EMAIL,
          to: user_name,
          subject: 'Please Confirm Your Email',
          text: `Hello! Confirm your email by visiting: ${verificationLink}`,
          html: `<p>Hello!</p><p>Please confirm your email by clicking the link below:</p><p><a href="${verificationLink}">${verificationLink}</a></p>`,
        });
        logger.info('Verification email sent (recipient redacted)');
      } catch (emailError) {
        logger.error('Failed to send verification email', {
          error: emailError.message,
        });
      }
      const data = { id: newUser.id, player_name };
      return jsonRes(res, '', data, 201);
    } catch (e) {
      logger.error('Error in /api_v1/user route', { error: e.message });
      return jsonRes(res, 'Server Error', [], 500);
    }
  };
