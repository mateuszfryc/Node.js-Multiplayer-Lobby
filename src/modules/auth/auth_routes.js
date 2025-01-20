import { asyncBoundry as bounds } from '#config/bounds.js';
import express from 'express';
import {
  loginAction,
  loginLimiter,
  loginSpeedLimiter,
} from './controller/auth_login_action.js';
import { logoutAction } from './controller/auth_logout_action.js';
import { refreshAction } from './controller/auth_refresh_action.js';
import { authenticateToken } from './middleware/authenticateToken.js';

export const authRoutes = (baseUrl, services) => {
  const router = express.Router();
  const authUrl = `${baseUrl}/auth`;
  const { database, envs } = services;
  const auth = authenticateToken(database);

  router
    .route(authUrl)
    .post(loginLimiter, loginSpeedLimiter, bounds(loginAction(database, envs)))
    .patch(bounds(refreshAction(database, envs)))
    .delete(auth, bounds(logoutAction(database)));

  return router;
};
