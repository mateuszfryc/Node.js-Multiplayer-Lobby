import jwt from 'jsonwebtoken';
import { loggedUsers } from '../state/auth_state.js';

export const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  const err = 'Token is invalid.';

  if (!token) {
    return res.status(401).json({ error: err });
  }

  // Check if the token is in the denylist
  if (!loggedUsers.has(token)) {
    return res.status(403).json({ error: err });
  }

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    req.user = user;
    next();
  } catch (err) {
    return res.status(403).json({ error: err });
  }
};
