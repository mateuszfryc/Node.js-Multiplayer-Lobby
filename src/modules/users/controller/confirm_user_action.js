import { logger } from '#config/logger.js';
import { htmlMessage } from '#utils/html.js';
import dayjs from 'dayjs';

export const confirmUserAction = (database) => async (req, res) => {
  const token = req.params.token;
  const now = dayjs().toISOString();
  const activation = await database.activation.findByToken(token);

  if (!activation) {
    logger.warn('Invalid token used for email confirmation');
    return res.status(404).send(htmlMessage('Link no longer valid.'));
  }

  if (dayjs(now).isAfter(dayjs(activation.expires_at))) {
    logger.warn('Expired token used for email confirmation');
    return res.status(400).send(htmlMessage('Link has expired.'));
  }

  const user = await database.user.findById(activation.user_id);
  if (user.validated_at) {
    logger.info('User is already validated');
    return res
      .status(200)
      .send(htmlMessage('Your account is already confirmed!'));
  }

  await database.user.update(activation.user_id, { validated_at: now });
  await database.activation.invalidate(token);
  logger.info('Email confirmed for a user');
  return res.status(200).send(htmlMessage('Email confirmed successfully!'));
};
