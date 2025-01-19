import { Router } from 'express';

import { asyncBoundry } from '#config/bounds.js';
import { DELETE, PATCH, POST } from '#config/consts.js';
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
  [
    [POST, authUrl, loginAction(database, envs), [loginLimiter, loginSpeedLimiter]],
    [PATCH, authUrl, refreshAction(database, envs), [jwtAuth]],
    [DELETE, authUrl, logoutAction(database), [jwtAuth]],
  ]
  .forEach(([method, url, action, middleware = []]) => {
    if (router[method]) router[method](url, ...middleware, asyncBoundry(action));
  });

  return router;
};
