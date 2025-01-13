import { tokens_denylist } from '#auth/state/auth_state.js';
import jwt from 'jsonwebtoken';

export const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  const err = { error: 'Token is invalid.' };

  if (!token) {
    return res.status(401).json(err);
  }

  // Check if the token is in the denylist
  if (tokens_denylist.has(token)) {
    return res.status(403).json(err);
  }

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    req.user = user;
    next();
  } catch (err) {
    console.error(`ERROR: ${err}`);
    return res.status(403).json(err);
  }
};
