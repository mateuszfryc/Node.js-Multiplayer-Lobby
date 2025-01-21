import { jsonRes } from '#utils/response.js';
import { logger } from './logger.js';

// single method to wrap all incomming requests in async
export const asyncBoundry = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// single method to wrap all incomming requests errors
export const errorBoundry = (err, req, res, next) => {
  logger.error(`${err.message}`, { stack: err.stack });

  // Once the headers are sent, you cannot modify the response (e.g., by sending a JSON error response). If you try to do so, it will result in an error.
  if (res.headersSent) {
    return next(err);
  }

  jsonRes(res, 'Internal Server Error', [], err.status || 500);
};
