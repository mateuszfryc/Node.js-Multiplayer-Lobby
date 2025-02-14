import { logger } from '#config/logger.js';
import bcrypt from 'bcrypt';
import dayjs from 'dayjs';
import { v4 as uuidv4 } from 'uuid';

export class GamesRepository {
  static STATUS_ALIVE = 'alive';
  static STATUS_UNRESPONSIVE = 'unresponsive';

  constructor(model) {
    this.model = model;
  }

  async findAll() {
    return this.model.findAll();
  }

  async findByIpPort(ip, port) {
    return this.model.findOne({ where: { ip, port } });
  }

  async findById(id) {
    return this.model.findOne({ where: { id } });
  }

  mapGameToGameListItem = (game) => ({
    // client searching for games need ip and port to measure its own ping to the host
    id: game.id,
    ip: game.ip,
    port: game.port,
    ping: game.ping,
    name: game.name,
    map_name: game.map_name,
    game_mode: game.game_mode,
    connected_players: game.connected_players.length,
    max_players: game.max_players,
    private: game.private,
    requires_password: game.password !== '',
    last_host_action_at: game.last_host_action_at,
    created_at: game.created_at,
  });

  async getCurrentGamesList() {
    const games = await this.model.findAll();
    if (games) return games.map((game) => this.mapGameToGameListItem(game));
    return [];
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
      connected_players: [ownerId], // owner is always connected
      max_players,
      private: isPrivate,
      password,
      ping: 0,
      created_at: now,
      updated_at: now,
      last_host_action_at: now,
      status: GamesRepository.STATUS_ALIVE,
    };
    return this.model.create(data);
  }

  async update(id, newData) {
    return this.model.update(newData, { where: { id } });
  }

  async setStatus(id, status) {
    if (
      ![
        GamesRepository.STATUS_ALIVE,
        GamesRepository.STATUS_UNRESPONSIVE,
      ].includes(status)
    ) {
      logger.error(`Invalid game status value: ${status}`);
      return;
    }
    return this.model.update({ status }, { where: { id } });
  }

  async delete(id) {
    return this.model.destroy({ where: { id } });
  }

  async refresh(id) {
    return this.model.update(
      { last_host_action_at: new Date(), status: GamesRepository.STATUS_ALIVE },
      { where: { id } }
    );
  }
}
