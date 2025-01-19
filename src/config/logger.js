import winston from 'winston';

const sensitiveKeys = [
  'password',
  'token',
  'refresh_token',
  'user_name',
  'ip',
  'port',
  'Authorization',
  'accessToken',
  'refreshToken',
];

const redactSensitiveData = winston.format((info) => {
  for (const key of sensitiveKeys) {
    if (info[key]) {
      info[key] = '[REDACTED]';
    }
  }
  return info;
});

export const logger = winston.createLogger({
  level: 'debug',
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
        winston.format.errors({ stack: true }),
        redactSensitiveData(),
        winston.format.colorize(),
        winston.format.printf(
          ({ level, message, timestamp, stack, ...meta }) => {
            const metaString = Object.keys(meta).length
              ? Object.entries(meta)
                  .map(([key, value]) => `${key}: "${value}"`)
                  .join(', ')
              : '';
            return `${timestamp} [${level}] ${stack || message} ${
              metaString ? `| ${metaString}` : ''
            }`;
          }
        )
      ),
    }),
    new winston.transports.DailyRotateFile({
      filename: './.logs/lobby-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '14d',
      format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
        winston.format.errors({ stack: true }),
        redactSensitiveData(),
        winston.format.json()
      ),
    }),
  ],
});

// middleware that logs incoming requests in details
export const requestLogger = (req, res, next) => {
  const { method, url, body, query, ip } = req;
  logger.info('Request', {
    method,
    url,
    ...body,
    ...query,
    ip,
  });
  next();
};
