import winston from 'winston';

const isProduction = process.env.NODE_ENV !== 'production';
const sensitiveKeys = [
  'accessToken',
  'Authorization',
  'clientIp',
  'ip',
  'password',
  'player_name',
  'port',
  'refresh_token',
  'refreshToken',
  'token',
  'user_name',
];

const redactSensitiveData = winston.format((info) => {
  for (const key of sensitiveKeys) {
    if (info[key]) {
      info[key] = '[REDACTED]';
    }
  }
  return info;
});

const formats = [
  winston.format.errors({ stack: true }),
  redactSensitiveData(),
  winston.format.colorize(),
  winston.format.printf(({ level, message, timestamp, stack, ...meta }) => {
    const metaString = Object.keys(meta).length
      ? Object.entries(meta)
          .map(([key, value]) => `${key}=${value}`)
          .join(', ')
      : '';
    return `${timestamp ? `${timestamp} ` : ''}[${level}] ${stack || message} ${
      metaString ? `${metaString}` : ''
    }`;
  }),
];

if (isProduction) {
  formats.unshift(
    winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' })
  );
}

export const logger = winston.createLogger({
  level: isProduction ? 'info' : 'debug',
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(...formats),
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
