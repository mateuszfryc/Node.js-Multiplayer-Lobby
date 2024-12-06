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
  return { mode, PORT };
};
