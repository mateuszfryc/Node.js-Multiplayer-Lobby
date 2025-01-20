import bcrypt from 'bcrypt';
import dayjs from 'dayjs';
import { v4 as uuidv4 } from 'uuid';

export class UserModel {
  constructor(model) {
    this.model = model;
  }
  async create(
    user_name,
    password,
    player_name,
    role = 'player',
    validated = false
  ) {
    const hashedPassword = await bcrypt.hash(password, 10);
    const now = dayjs().toISOString();
    const data = {
      id: uuidv4(),
      user_name,
      password: hashedPassword,
      player_name,
      role,
      created_at: now,
      updated_at: now,
      validated_at: validated ? now : null,
      refresh_token: null,
    };
    return this.model.create(data);
  }
  async findById(id) {
    return this.model.findOne({ where: { id } });
  }
  async findByUserName(user_name) {
    return this.model.findOne({ where: { user_name } });
  }
  async update(id, newData) {
    return this.model.update(newData, { where: { id } });
  }
  async login(user, refreshToken) {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    await this.update(user.id, {
      refresh_token: hashedRefreshToken,
      updated_at: dayjs().toISOString(),
    });
  }
  async logout(userId) {
    await this.update(userId, {
      refresh_token: null,
      updated_at: dayjs().toISOString(),
    });
  }

  async delete(userId) {
    return this.model.destroy({ where: { id: userId } });
  }
}
