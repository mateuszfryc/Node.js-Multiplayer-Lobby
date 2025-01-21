import { DataTypes } from 'sequelize';

export const gamesSchema = (database_manager) =>
  database_manager.define(
    'game',
    // prettier-ignore
    {
        id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
        owner_id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, allowNull: false },
        ip: { type: DataTypes.STRING, allowNull: false },
        port: { type: DataTypes.INTEGER, allowNull: false },
        name: { type: DataTypes.STRING, allowNull: false },
        map_name: { type: DataTypes.STRING, allowNull: false },
        game_mode: { type: DataTypes.STRING, allowNull: false },
        connected_players: { type: DataTypes.ARRAY(DataTypes.STRING), allowNull: false, defaultValue: [] },
        max_players: { type: DataTypes.INTEGER, allowNull: false },
        private: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
        password: { type: DataTypes.STRING, allowNull: false, defaultValue: '' },
        ping: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
        last_host_action_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
        status: { type: DataTypes.STRING, allowNull: false, defaultValue: 'alive' },
      },
    {
      tableName: 'games',
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at',
    }
  );
