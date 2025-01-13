import express from 'express';

import { authenticateToken } from '#auth/middleware/auth_token.js';
import { login, logout, test_auth } from '#auth/requests/auth_requests.js';

export const auth_router = express.Router();

auth_router.post('/login', login);
auth_router.post('/logout', authenticateToken, logout);
auth_router.get('/test_auth', authenticateToken, test_auth);
