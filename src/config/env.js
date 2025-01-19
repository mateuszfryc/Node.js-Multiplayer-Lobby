import dotenv from 'dotenv';
import fs from 'fs';
import { logger } from './logger.js';

// check for required environment variables and format them based on type
export const ensureEnvs = async (envDefinitions) => {
  const envs = {};
  const isProduction = process.env.NODE_ENV === 'production';
  if (isProduction) {
    dotenv.config({ path: '.env.prod.db' });
    dotenv.config({ path: '.env.prod.auth' });
  } else {
    dotenv.config({ path: '.env.db' });
    dotenv.config({ path: '.env.auth' });
  }
  const parseBoolean = (value) => {
    if (value === 'true') return true;
    if (value === 'false') return false;
    throw new Error(`Invalid boolean value: "${value}".`);
  };
  for (const {
    key,
    minLength,
    base64Length,
    filePath,
    type,
    log,
  } of envDefinitions) {
    const value = process.env[key];
    if (!value)
      throw new Error(`Missing required environment variable: ${key}`);
    if (minLength && value.length < minLength) {
      throw new Error(
        `Environment variable "${key}" must be at least ${minLength} characters.`
      );
    }
    if (base64Length && value) {
      const raw = Buffer.from(value, 'base64');
      if (raw.length !== base64Length) {
        throw new Error(
          `Environment variable "${key}" must decode to ${base64Length} bytes.`
        );
      }
    }
    if (filePath && value) {
      try {
        fs.accessSync(value, fs.constants.R_OK);
      } catch {
        throw new Error(
          `File in "${key}" does not exist or is not readable: ${value}`
        );
      }
    }
    if (log) {
      logger.info(`"${key}": ${value}.`);
    }
    switch (type) {
      case 'bool':
        envs[key] = parseBoolean(value);
        break;
      case 'number': {
        const numericValue = Number(value);
        if (isNaN(numericValue)) {
          throw new Error(
            `Environment variable "${key}" must be a valid number.`
          );
        }
        envs[key] = numericValue;
        break;
      }
      default:
        envs[key] = value;
    }
  }
  logger.info('All required environment variables are present and valid.');
  return envs;
};
