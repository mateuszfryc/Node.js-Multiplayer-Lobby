export const envDefinitions = [
  { key: 'NODE_ENV' },
  { key: 'PORT', type: 'int', log: true },

  // security
  { key: 'USE_SSL', type: 'bool' },
  { key: 'SSL_KEY_PATH' },
  { key: 'SSL_CERT_PATH' },

  // auth
  { key: 'JWT_SECRET', minLength: 32 },
  { key: 'JWT_REFRESH_SECRET', minLength: 32 },

  // admin
  { key: 'ADMIN_USER_NAME' },
  { key: 'ADMIN_PASSWORD' },
  { key: 'ADMIN_PLAYER_NAME' },
  { key: 'ALLOW_USER_REGISTRATION', log: true },

  // database
  { key: 'DB_USER' },
  { key: 'DB_PASSWORD' },
  { key: 'DB_NAME' },
  { key: 'DB_HOST' },
  { key: 'DB_PORT', type: 'int' },
  { key: 'DB_FORCE_SYNC', type: 'bool', log: true },

  // smpt mailer
  { key: 'SMTP_HOST' },
  { key: 'FROM_EMAIL' },
  { key: 'SMTP_USER' },
  { key: 'SMTP_PASS' },
  { key: 'SMTP_PORT' },

  // games
  { key: 'GAME_HEARTBEAT_INTERVAL', type: 'int', log: true },
  { key: 'NUMBER_OF_ALLOWED_SKIPPED_HEARTBEATS', type: 'int', log: true },
  { key: 'INACTIVE_GAME_TIMEOUT', type: 'int', log: true },
  { key: 'ALLOW_MULTIPLE_GAMES_PER_HOST', type: 'bool', log: true },
];
