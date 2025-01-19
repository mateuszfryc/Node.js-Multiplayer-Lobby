import nodemailer from 'nodemailer';
import { logger } from './logger.js';

export const transporter = (envs) => {
  const smptPort = parseInt(envs.SMTP_PORT || '587', 10);
  const client = nodemailer.createTransport({
    host: envs.SMTP_HOST,
    port: smptPort,
    secure: smptPort === 465,
    auth: {
      user: envs.SMTP_USER,
      pass: envs.SMTP_PASS,
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
