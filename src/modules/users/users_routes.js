import { asyncBoundry } from '#config/bounds.js';
import { DELETE, GET, POST, PUT } from '#config/consts.js';
import { Router } from 'express';

import { authenticateToken } from '#auth/middleware/authenticateToken.js';
import { confirmUserAction } from './actions/confirm_user_action.js';
import { createUserAction } from './actions/create_user_action.js';
import { deleteUserAction } from './actions/delete_user_action.js';
import { getUserAction } from './actions/get_user_action.js';
import { updateUserAction } from './actions/update_user_action.js';

export const usersRoutes = (baseUrl, services) => {
  const router = Router();
  const url = `${baseUrl}/users`;
  const { database, envs, mailer } = services;
  const jwtAuth = authenticateToken(database);

  // prettier-ignore
  [
    [GET, `${url}/:user_id`,getUserAction(database), [jwtAuth]],
    [POST, url, createUserAction(database, envs, mailer), [jwtAuth]],
    [PUT, `${url}/:user_id`, updateUserAction(database), [jwtAuth]],
    [DELETE, `${url}/:user_id`, deleteUserAction(database), [jwtAuth]],
    [GET, `${url}/verify/:token`, confirmUserAction(database)],
  ]
  .forEach(([method, url, action, middleware = []]) => {
    if (router[method]) router[method](url, ...middleware, asyncBoundry(action));
  });

  return router;
};
