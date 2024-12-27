import bodyParser from 'body-parser';
import cors from 'cors';
import express from 'express';
import helmet from 'helmet';

import { auth_router } from './modules/auth/routes/auth_routes.js';
import { cors_config } from './modules/global/config/cors.js';
import { loadEnv } from './modules/global/config/dotenv.js';
import { limiter } from './modules/global/config/limiter.js';
import { isProd } from './utils/env.js';

const { mode, PORT } = loadEnv();
console.log(`Running in "${mode}" mode`);

const app = express();
app.use(helmet());
app.use(cors(cors_config));
app.use(bodyParser.json());
app.use(limiter);

if (isProd()) {
  // Trust the first proxy
  app.set('trust proxy', 1);
}

app.get('/', (req, res) => {
  res.status(200).send('Ready.');
});
app.use('/api', auth_router);

app.listen(PORT, () => {
  console.log('Server is running on port 3000');
});
