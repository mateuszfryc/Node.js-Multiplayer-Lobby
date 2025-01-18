import bcrypt from 'bcrypt';
import dayjs from 'dayjs';
import { v4 as uuidv4 } from 'uuid';

export class GameModel {
  constructor(model) {
    this.model = model;
  }
  async findAllGames() {
    return this.model.findAll();
  }
  async findByIpPort(ip, port) {
    return this.model.findOne({ where: { ip, port } });
  }
  async findById(id) {
    return this.model.findOne({ where: { id } });
  }
  async create(
    ownerId,
    ip,
    port,
    name,
    map_name,
    game_mode,
    max_players = 8,
    isPrivate = false,
    pass = null
  ) {
    const now = dayjs().toISOString();
    const password = pass ? await bcrypt.hash(pass, 10) : '';
    const data = {
      id: uuidv4(),
      owner_id: ownerId,
      ip,
      port,
      name,
      map_name,
      game_mode,
      connected_players: [],
      max_players,
      private: isPrivate,
      password,
      ping: 0,
      created_at: now,
      updated_at: now,
    };
    return this.model.create(data);
  }
  async updateGame(id, newData) {
    return this.model.update(newData, { where: { id } });
  }
  async deleteGame(id) {
    return this.model.destroy({ where: { id } });
  }
}
