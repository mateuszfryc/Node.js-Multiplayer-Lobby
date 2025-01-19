import { asyncBoundry } from '#config/bounds.js';
import { Router } from 'express';

/*
Example usage:
  import { DELETE, GET, POST, PUT } from '#config/consts.js';

  const routes = [
    [GET, `${url}/:user_id`,getUserAction(database), [jwtAuth]],
    [POST, url, createUserAction(database, envs, mailer), [jwtAuth]],
    [PUT, `${url}/:user_id`, updateUserAction(database), [jwtAuth]],
    [DELETE, `${url}/:user_id`, deleteUserAction(database), [jwtAuth]],
    [GET, `${url}/verify/:token`, confirmUserAction(database)],
  ]
  const router = defineRouter(routes);
*/

export const defineRouter = (routes) => {
  const router = Router();
  routes.forEach(([method, url, action, middleware = []]) => {
    if (router[method]) {
      router[method](url, ...middleware, asyncBoundry(action));
    }
  });
  return router;
};
