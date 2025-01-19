import { DELETE, PATCH, POST } from '#config/consts.js';
import { defineRouter } from '#utils/routing.js';
import {
  loginAction,
  loginLimiter,
  loginSpeedLimiter,
} from './actions/auth_login_action.js';
import { logoutAction } from './actions/auth_logout_action.js';
import { refreshAction } from './actions/auth_refresh_action.js';
import { authenticateToken } from './middleware/authenticateToken.js';

export const authRoutes = (baseUrl, services) => {
  const authUrl = `${baseUrl}/auth`;
  const { database, envs } = services;
  const jwtAuth = authenticateToken(database);

  // prettier-ignore
  const routes = [
    [POST, authUrl, loginAction(database, envs), [loginLimiter, loginSpeedLimiter]],
    [DELETE, authUrl, logoutAction(database), [jwtAuth]],
    [PATCH, authUrl, refreshAction(database, envs)],
  ]

  return defineRouter(routes);
};
