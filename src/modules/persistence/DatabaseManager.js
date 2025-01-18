import { logger } from '#config/logger.js';
import { GameModel } from '#games/models/game_model.js';
import { UserModel } from '#users/models/user_model.js';
import { Sequelize } from 'sequelize';
import { ActivationModel } from './models/activation_mode.js';

/* This class abstracts away database implementation. */
export class DatabaseManager {
  constructor(ENVS, inUsersSchema, inGamesSchema, inActivationsSchema) {
    const isProduction = ENVS.NODE_ENV === 'production';
    this.sequelize = new Sequelize(
      ENVS.DB_NAME,
      ENVS.DB_USER,
      ENVS.DB_PASSWORD,
      {
        host: ENVS.DB_HOST,
        dialect: 'postgres',
        protocol: 'postgres',
        logging: false,
        define: {
          schema: 'public',
        },
        dialectOptions: isProduction
          ? {
              ssl: {
                require: true,
                rejectUnauthorized: false,
              },
            }
          : {},
      }
    );
    this.user = new UserModel(inUsersSchema(this.sequelize));
    this.game = new GameModel(inGamesSchema(this.sequelize));
    this.activation = new ActivationModel(inActivationsSchema(this.sequelize));
  }

  async init(ENVS, activeGames) {
    try {
      await this.sequelize.authenticate();
      logger.info('Database connection successful.');
    } catch (error) {
      logger.error('Database connection failed:', error.message);
      process.exit(1);
    }

    if (ENVS.DB_FORCE_SYNC) {
      logger.info('Syncing database tables');
      await this.sequelize.sync({ force: true });
    }

    try {
      if (
        !ENVS.ADMIN_USER_NAME ||
        !ENVS.ADMIN_PASSWORD ||
        !ENVS.ADMIN_PLAYER_NAME
      ) {
        throw new Error('Admin user environment variables are missing.');
      }
      const existingAdmin = await this.user.findUserByName(
        ENVS.ADMIN_USER_NAME
      );
      if (existingAdmin) {
        logger.info('Admin user already exists');
      } else {
        await db.user.create(
          ENVS.ADMIN_USER_NAME,
          ENVS.ADMIN_PASSWORD,
          ENVS.ADMIN_PLAYER_NAME,
          'admin',
          true
        );
        logger.info('Admin user created successfully');
      }
    } catch (error) {
      logger.error('Failed to create admin user', { error: error.message });
      process.exit(1);
    }

    const games = await this.game.findAllGames();
    // if before the server went down there where any active games push them into activeGames array
    games.forEach((game) => {
      activeGames.set(game.id, game.toJSON());
    });
  }
}
