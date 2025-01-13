import bodyParser from 'body-parser';
import cors from 'cors';
import express from 'express';
import helmet from 'helmet';

import { auth_router } from '#auth/routes/auth_routes.js';
import { cors_config } from '#config/cors.js';
import { setupDb } from '#config/database.js';
import { loadEnv } from '#config/dotenv.js';
import { limiter } from '#config/limiter.js';
import { rooms_router } from '#rooms/routes/rooms_routes.js';
import { isProd } from '#utils/env.js';

const { mode, PORT } = loadEnv();
console.log(`Running in "${mode}" mode`);

await setupDb();

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
[auth_router, rooms_router].forEach((router) => app.use('/api', router));

app.listen(PORT, () => {
  console.log(`Server is running on port: ${PORT}`);
});
