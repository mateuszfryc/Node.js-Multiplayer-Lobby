import { Router } from 'express';

import { authenticateToken } from '#auth/middleware/auth_jwt.js';
import { confirmUserAction } from './actions/confirm_user_action.js';
import { createUserAction } from './actions/create_user_action.js';
import { deleteUserAction } from './actions/delete_user_action.js';
import { updateUserAction } from './actions/update_user_action.js';

export const usersRoutes = (baseUrl, services) => {
  const router = Router();
  const url = `${baseUrl}/users`;
  const { database } = services;
  const jwtAuth = authenticateToken(database);

  // prettier-ignore
  {
    router.post(url, jwtAuth, createUserAction(database));
    router.put(`${url}/:user_id`, jwtAuth, updateUserAction(database));
    router.delete(`${url}/:user_id`, jwtAuth, deleteUserAction(database));
    router.patch(`${url}/:token`, confirmUserAction(database));
  }

  return router;
};
