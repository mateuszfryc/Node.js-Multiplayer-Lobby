import { ActivationsRepository } from '#auth/persistence/activations_repository.js';
import { logger } from '#config/logger.js';
import { GamesRepository } from '#games/persistence/games_repository.js';
import { UsersRepository } from '#users/persistence/users_repository.js';
import { Sequelize } from 'sequelize';

/* This class abstracts away database implementation. */
export class DatabaseManager {
  constructor(envs, inUsersSchema, inGamesSchema, inActivationsSchema) {
    const isProduction = envs.NODE_ENV === 'production';
    this.sequelize = new Sequelize(
      envs.DB_NAME,
      envs.DB_USER,
      envs.DB_PASSWORD,
      {
        host: envs.DB_HOST,
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
    this.user = new UsersRepository(inUsersSchema(this.sequelize));
    this.game = new GamesRepository(inGamesSchema(this.sequelize));
    this.activation = new ActivationsRepository(
      inActivationsSchema(this.sequelize)
    );
  }

  async init(database, envs) {
    try {
      await this.sequelize.authenticate();
      logger.info('Database connection successful.');
    } catch (error) {
      logger.error('Database connection failed:', error.message);
      process.exit(1);
    }

    if (envs.DB_FORCE_SYNC) {
      logger.info('Syncing database tables');
      await this.sequelize.sync({ force: true });
    }

    try {
      if (
        !envs.ADMIN_USER_NAME ||
        !envs.ADMIN_PASSWORD ||
        !envs.ADMIN_PLAYER_NAME
      ) {
        throw new Error('Admin user environment variables are missing.');
      }
      const existingAdmin = await this.user.findByUserName(
        envs.ADMIN_USER_NAME
      );
      if (existingAdmin) {
        logger.info('Admin user already exists');
      } else {
        await database.user.create(
          envs.ADMIN_USER_NAME,
          envs.ADMIN_PASSWORD,
          envs.ADMIN_PLAYER_NAME,
          'admin',
          true
        );
        logger.info('Admin user created successfully');
      }
    } catch (error) {
      logger.error('Failed to create admin user', { error: error.message });
      process.exit(1);
    }

    const games = await this.game.findAll();
  }
}
