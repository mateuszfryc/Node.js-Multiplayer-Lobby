import { USER_CHARS } from '#config/consts.js';
import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';
import { validateIpOrLocalhost, validatePort } from '#utils/validators.js';

export const createGameAction =
  (database, activeGames, websockets, envs) => async (req, res) => {
    const { requestingUser } = req.body;
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

    if (!envs.ALLOW_MULTIPLE_GAMES_PER_HOST) {
      const user = await database.user.findById(requestingUser.id);
      const hostedGames = user.hosted_games ?? [];
      if (hostedGames.length > 0) {
        logger.warn(
          'User tried to create more than one game when ALLOW_MULTIPLE_GAMES_PER_HOST is set to false.'
        );
        return jsonRes(res, 'Multiple games hosting not allowed', [], 403);
      }
    }

    const existing = await database.game.findByIpPort(ip, port);
    if (existing) {
      logger.debug('Existing game found for IP:Port. Replacing game entry');
      await database.game.delete(existing.id);
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
    websockets.emit('new_game', newGame);
    logger.info('Game created successfully', {
      game_name,
      map_name,
      game_mode,
      max_players,
      private: isPrivate,
    });

    const user = await database.user.findById(requestingUser.id);
    logger.info('user: ', requestingUser);
    const hostedGames = user.hosted_games ?? [];
    await database.user.update(requestingUser.id, {
      hosted_games: [...hostedGames, newGame.id],
    });

    return jsonRes(
      res,
      '',
      {
        game: newGame,
        settings: { heartbeatIntervalSeconds: envs.GAME_HEARTBEAT_INTERVAL },
      },
      201
    );
  };
