import pg from 'pg';
import { isProd } from '../../../utils/env.js';

let pool;

export const db = () => {
  if (!pool) {
    pool = new pg.Pool({
      user: process.env.DB_USER,
      host: process.env.DB_HOST,
      database: process.env.DB_NAME,
      password: process.env.DB_PASSWORD,
      port: process.env.DB_PORT || 5432,
      ssl: isProd() ? { rejectUnauthorized: false } : false,
    });
  }
  return pool;
};
