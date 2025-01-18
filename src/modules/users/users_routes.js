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

  // prettier-ignore
  {
    router.post(url, authenticateToken, createUserAction(database));
    router.put(`${url}/:user_id`, authenticateToken, updateUserAction(database));
    router.delete(`${url}/:user_id`, authenticateToken, deleteUserAction(database));
    router.patch(`${url}/:token`, confirmUserAction(database));
  }

  return router;
};
