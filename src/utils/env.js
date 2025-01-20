import dotenv from 'dotenv';
import fs from 'fs';

function parseEnv(value, type) {
  switch (type) {
    case 'bool':
      return value.toLowerCase() === 'true'; // Parse "true" to true, "false" to false
    case 'int':
      return parseInt(value, 10); // Parse to integer
    case 'float':
      return parseFloat(value); // Parse to float
    case 'string':
    default:
      return value; // Return as string
  }
}

// check for required environment variables and format them based on type
export const ensureEnvs = async (envDefinitions) => {
  const envs = {};
  const isProduction = process.env.NODE_ENV === 'production';
  dotenv.config({ path: isProduction ? '.env.prod' : '.env' });

  for (const {
    key,
    minLength,
    base64Length,
    filePath,
    type,
    log,
  } of envDefinitions) {
    const value = process.env[key];

    if (!value) {
      throw new Error(`Missing required environment variable: ${key}`);
    }

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
      console.log(`${key}: ${value}.`);
    }
    envs[key] = parseEnv(value, type);
  }

  console.log('All required environment variables are present and valid.');
  return envs;
};
