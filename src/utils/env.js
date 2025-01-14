import dotenv from 'dotenv';

export const loadEnv = () => {
  let mode = null;
  if (process.env.NODE_ENV == 'production') {
    dotenv.config({ path: '.env.prod.db' });
    dotenv.config({ path: '.env.prod.auth' });
    mode = 'production';
  }
  if (process.env.NODE_ENV == 'development') {
    dotenv.config({ path: '.env.db' });
    dotenv.config({ path: '.env.auth' });
    mode = 'development';
  }
  if (mode === null) {
    throw new Error('Error: NODE_ENV not set');
  }

  const PORT = process.env.PORT ?? 3000;
  const isProd = mode === 'production';

  // List of required variables and any constraints we want to check
  const requiredVars = [
    { key: 'JWT_SECRET', minLength: 32 },
    { key: 'JWT_REFRESH_SECRET', minLength: 32 },
    // For SODIUM_KEY, it must be a valid base64-encoded 32-byte key
    { key: 'SODIUM_KEY', base64Length: 32 },
  ];

  for (const { key, minLength, base64Length } of requiredVars) {
    const value = process.env[key];
    if (!value) {
      throw new Error(`Missing required environment variable: ${key}`);
    }

    // If we have a plain minimum-length requirement (e.g., for JWT secrets)
    if (minLength && value.length < minLength) {
      throw new Error(
        `Environment variable "${key}" must be at least ${minLength} characters long (current length: ${value.length}).`
      );
    }

    // If we require a base64-encoded 32-byte key (e.g., for SODIUM_KEY)
    if (base64Length) {
      const raw = Buffer.from(value, 'base64');
      if (raw.length !== base64Length) {
        throw new Error(
          `Environment variable "${key}" must be a valid base64-encoded string that decodes to ${base64Length} bytes.`
        );
      }
    }
  }

  if (isProd) {
    const dbVars = ['DB_USER', 'DB_PASS', 'DB_NAME', 'DB_HOST', 'DB_PORT'];
    for (const key of dbVars) {
      if (!process.env[key]) {
        throw new Error(`Missing required environment variable: ${key}`);
      }
    }
  }

  // If everything passed, no errors are thrown, so we’re good
  console.log('All required environment variables are present and valid.');

  return [mode, PORT, isProd];
};

export const isProd = () => process.env.NODE_ENV === 'production';
export const isDev = () => process.env.NODE_ENV === 'development';

export const getJwtTimoutSeconds = () => {
  const timeout = process.env.JWT_EXPIRATION;

  // check if its a digit
  if (!isNaN(timeout)) {
    return parseInt(timeout);
  }

  // check last character for time suffix
  const suffix = timeout.slice(-1);
  if (!isNaN(suffix)) {
    return parseInt(timeout);
  }

  // get the value without the suffix
  const value = parseInt(timeout.slice(0, -1));
  // convert the value to seconds
  switch (suffix) {
    case 'm': // minutes
      return value * 60;
    case 'h': // hours
      return value * 60 * 60;
    case 'd': // days
      return value * 60 * 60 * 24;
    case 'w': // weeks
      return value * 60 * 60 * 24 * 7;
    case 'M': // months
      return value * 60 * 60 * 24 * 30;
    case 'y': // years
      return value * 60 * 60 * 24 * 365;
    default: // seconds
      return value;
  }
};
