import { jsonRes } from '#utils/response.js';
import { logger } from './logger.js';

// single method to wrap all incomming requests
export const asyncBoundry = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// single method to wrap all incomming errors
export const errorBoundry = (err, req, res, next) => {
  logger.error(`[Error] ${err.message}`, { stack: err.stack });

  jsonRes(res, 'Internal Server Error', [], err.status || 500);
};
