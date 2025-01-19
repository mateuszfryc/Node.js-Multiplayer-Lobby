import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';
import dayjs from 'dayjs';

export const confirmUserAction = (database) => async (req, res) => {
  const token = req.params.token;
  const now = dayjs().toISOString();
  const act = await database.activation.findByToken(token);
  if (!act) {
    logger.warn('Invalid token used for email confirmation');
    return jsonRes(res, 'Invalid token', [], 404);
  }
  if (dayjs(now).isAfter(dayjs(act.expires_at))) {
    logger.warn('Expired token used for email confirmation');
    return jsonRes(res, 'Invalid token', [], 400);
  }
  await database.user.updateUser(act.user_id, { validated_at: now });
  logger.info('Email confirmed for a user');
  return jsonRes(res, '', [], 200);
};
