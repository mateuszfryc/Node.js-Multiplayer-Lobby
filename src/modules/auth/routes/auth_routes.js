import express from 'express';

import { login, logout, test_auth } from '../controllers/auth_controllers.js';
import { authenticateToken } from '../middleware/auth_token.js';

export const auth_router = express.Router();

auth_router.post('/login', login);
auth_router.post('/logout', authenticateToken, logout);
auth_router.get('/test_auth', authenticateToken, test_auth);
