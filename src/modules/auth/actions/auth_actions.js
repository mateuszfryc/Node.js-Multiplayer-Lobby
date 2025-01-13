import { db } from '#config/database.js';
// Fetch user by email
export const getUserByEmail = async (email) => {
  return db.User.findOne({ where: { email } });
};

// Update user's timeout_date
export const updateUserTimeout = async (userId, timeoutDate) => {
  return db.User.update(
    { timeout_date: timeoutDate },
    { where: { id: userId } }
  );
};
