import { Router } from 'express';

import {
  loginAction,
  loginLimiter,
  loginSpeedLimiter,
} from './actions/auth_login_action.js';
import { logoutAction } from './actions/auth_logout_action.js';
import { refreshAction } from './actions/auth_refresh_action.js';
import { authenticateToken } from './middleware/authenticateToken.js';

export const authRoutes = (baseUrl, services) => {
  const router = Router();
  const authUrl = `${baseUrl}/auth`;
  const { database, envs } = services;
  const jwtAuth = authenticateToken(database);

  // prettier-ignore
  {
    router.post(authUrl, loginLimiter, loginSpeedLimiter, loginAction(database, envs));
    router.patch(authUrl, refreshAction(database, envs));
    router.delete(authUrl, jwtAuth, logoutAction(database));
  }

  return router;
};
