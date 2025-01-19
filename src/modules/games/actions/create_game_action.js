import { USER_CHARS } from '#config/consts.js';
import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';
import { validateIpOrLocalhost, validatePort } from '#utils/validators.js';

export const createGameAction =
  (database, activeGames, websockets) => async (req, res) => {
    logger.info('POST /api_v1/games called', {
      method: req.method,
      url: req.url,
      clientIp: req.ip,
    });
    try {
      const { requestingUser } = req.body;
      logger.debug('Decoded user role for creating game', {
        role: requestingUser?.role,
      });
      if (!requestingUser || !requestingUser.id) {
        logger.warn('Unauthorized attempt to create game');
        return jsonRes(res, 'Unauthorized', [], 401);
      }
      let {
        ip,
        port,
        game_name,
        map_name,
        game_mode,
        max_players,
        private: isPrivate,
        password,
      } = req.body;
      if (!ip || !port || !game_name || !map_name || !game_mode) {
        logger.warn('Missing required fields in create game request');
        return jsonRes(res, 'Missing fields', [], 400);
      }
      if (!validateIpOrLocalhost(ip)) {
        logger.warn('Invalid IP address for game creation');
        return jsonRes(res, 'Incorrect IP address', [], 400);
      }
      if (!validatePort(port)) {
        logger.warn('Invalid port number for game creation');
        return jsonRes(res, 'Incorrect port number', [], 400);
      }
      if (
        !USER_CHARS.test(game_name) ||
        !USER_CHARS.test(map_name) ||
        !USER_CHARS.test(game_mode)
      ) {
        logger.warn('Invalid characters in game fields');
        return jsonRes(res, 'Invalid characters', [], 400);
      }
      if (!max_players) max_players = 8;
      if (!isPrivate) isPrivate = false;
      const existing = await database.game.findByIpPort(ip, port);
      if (existing) {
        logger.debug('Existing game found for IP:Port. Replacing game entry');
        await database.game.deleteGame(existing.id);
        activeGames.delete(existing.id);
      }

      const newGame = await database.game.create(
        requestingUser.id,
        ip,
        port,
        game_name,
        map_name,
        game_mode,
        max_players,
        isPrivate,
        password
      );
      activeGames.set(newGame.id, newGame.toJSON());
      logger.info('Game created successfully', {
        game_name,
        map_name,
        game_mode,
        max_players,
        private: isPrivate,
      });
      websockets.emit('game_created', newGame);
      return jsonRes(res, '', newGame, 201);
    } catch (e) {
      logger.error('Error in POST /api_v1/games route', { error: e.message });
      return jsonRes(res, 'Server Error', [], 500);
    }
  };
