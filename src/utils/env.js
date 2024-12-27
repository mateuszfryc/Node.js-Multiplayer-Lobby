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
