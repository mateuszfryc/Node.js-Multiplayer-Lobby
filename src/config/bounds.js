import { jsonRes } from '#utils/response.js';
import { logger } from './logger.js';

// single method to wrap all incomming requests in async
export const asyncBoundry = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// single method to wrap all incomming requests errors
export const errorBoundry = (err, req, res, next) => {
  logger.error(`${err.message}`, { stack: err.stack });

  jsonRes(res, 'Internal Server Error', [], err.status || 500);
};
