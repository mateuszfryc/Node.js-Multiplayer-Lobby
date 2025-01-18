import nodemailer from 'nodemailer';
import { logger } from './logger.js';

export const transporter = (ENVS) => {
  const smptPort = parseInt(ENVS.SMTP_PORT || '587', 10);
  const client = nodemailer.createTransport({
    host: ENVS.SMTP_HOST,
    port: smptPort,
    secure: smptPort === 465,
    auth: {
      user: ENVS.SMTP_USER,
      pass: ENVS.SMTP_PASS,
    },
  });

  client.verify((error, success) => {
    if (error) {
      logger.error('SMTP Connection Error', { error: error.message });
    } else {
      logger.info('SMTP Connection Successful');
    }
  });

  return client;
};
