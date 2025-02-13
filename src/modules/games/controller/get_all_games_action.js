import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';

const mapGameToGameListItem = (game) => ({
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

export const getAllGamesAction = (database) => async (req, res) => {
  const games = await database.game.findAll();
  if (games === undefined || games === null) {
    logger.warn('Could not retrieve games list from database');
    return jsonRes(res, 'Internal Server Error', [], 500);
  }
  logger.debug('Fetched games list', { count: games.length });
  return jsonRes(
    res,
    '',
    games.map((game) => mapGameToGameListItem(game)),
    200
  );
};
