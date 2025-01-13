import express from 'express';

import { authenticateToken } from '#auth/middleware/auth_token.js';
import { getRooms } from '#rooms/requests/rooms_requests.js';

export const rooms_router = express.Router();

rooms_router.get('/rooms', authenticateToken, getRooms);
