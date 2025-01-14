import jwt from 'jsonwebtoken';
import validator from 'validator';

import {
  getUserByEmail,
  updateUserTimeout,
} from '#auth/actions/auth_actions.js';
import { tokens_denylist } from '#auth/state/auth_state.js';
import { getJwtTimoutSeconds, isDev } from '#utils/env.js';

// Route to handle login requests
export const login = async (req, res) => {
  const { email, password } = req.body;
  const error = { error: 'Invalid email or password' };
  const prfx = 'User Login:';

  try {
    // check if either is string
    if (typeof email !== 'string' || typeof password !== 'string') {
      console.log(
        `${prfx} Email is not a string: ${email} of type ${typeof email}`
      );
      return res.status(400).json(error);
    }

    if (!validator.isEmail(email)) {
      console.log(`${prfx} Invalid email format: ${email}`);
      return res.status(400).json(error);
    } else {
      console.log(`${prfx} Valid email format: ${email}`);
    }

    const user = await getUserByEmail(email);
    if (!user) {
      console.log(
        `${prfx} Invalid user databse entry: ${user} of type ${typeof user}`
      );
      return res.status(401).json(error);
    } else {
      console.log(`${prfx} Valid user databse entry: ${user}`);
    }

    if (user.timeout_date > 0 && user.timeout_date > Date.now()) {
      console.log(
        `${prfx} User already logged in attempted to log in again, id: ${user.id}`
      );
      return res.status(401).json(error);
    } else {
      console.log(`${prfx} User not logged in, id: ${user.id}`);
    }

    const isPasswordValid = await user.verifyPassword(user.password);

    if (!isPasswordValid) {
      console.log(`${prfx} Invalid password: ${password}`);
      return res.status(401).json(error);
    } else {
      console.log(`${prfx} Valid password: ${password}`);
    }

    const timeout = getJwtTimoutSeconds();

    // Generate a JWT token
    const token = jwt.sign(
      { id: user.id, display_name: user.display_name }, // Payload
      process.env.JWT_SECRET, // Secret key
      { expiresIn: timeout } // Token expiration
    );

    // Update the user's timeout date in the database
    console.log(`${prfx} Updating user timeout date: ${user.id}`);
    await updateUserTimeout(user.id, Date.now() + timeout);

    console.log(
      `${prfx} User logged in, id: ${user.id}, display_name: ${user.display_name}, JWT expires in: ${timeout} seconds, timeout_date: ${user.timeout_date}`
    );

    res.status(200).json({
      message: 'Login successful',
      token,
    });
  } catch (err) {
    console.error(`${prfx} ERROR: ${err}`);
    res.status(500).json({ error: 'Internal server error' });
  }
};

export const logout = (req, res) => {
  const token = req.headers['authorization'].split(' ')[1];

  // Add the token to the denylist
  tokens_denylist.add(token);

  res.status(200).json({ message: 'Logged out successfully' });
};

export const test_auth = async (req, res) => {
  if (!isDev()) {
    console.log(
      'Access denied to protected route, test_auth is only available in development mode'
    );
    return;
  }

  res.status(200).json({
    message: 'Access granted to protected route',
  });
};
