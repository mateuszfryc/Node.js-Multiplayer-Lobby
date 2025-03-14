import { asyncBoundry as bounds } from '#config/bounds.js';
import express from 'express';

import { authenticateToken } from '#auth/middleware/authenticateToken.js';
import { confirmUserAction } from './controller/confirm_user_action.js';
import { createUserAction } from './controller/create_user_action.js';
import { deleteUserAction } from './controller/delete_user_action.js';
import { getUserAction } from './controller/get_user_action.js';
import { updateUserAction } from './controller/update_user_action.js';

export const usersRoutes = (baseUrl, services) => {
  const router = express.Router();
  const { database, envs, mailer, websockets } = services;
  const auth = authenticateToken(database);

  if (envs.ALLOW_USER_REGISTRATION) {
    router
      .route(`${baseUrl}/users`)
      .post(bounds(createUserAction(database, envs, mailer)));
  } else {
    router
      .route(`${baseUrl}/users`)
      .post(auth, bounds(createUserAction(database, envs, mailer)));
  }

  router
    .route(`${baseUrl}/users/:user_id`)
    .get(auth, bounds(getUserAction(database)))
    .put(auth, bounds(updateUserAction(database)))
    .delete(auth, bounds(deleteUserAction(database, websockets)));

  router
    .route(`${baseUrl}/users/verify/:token`)
    .get(bounds(confirmUserAction(database)));

  return router;
};
