import { DataTypes } from 'sequelize';

export const userSchema = (database_manager) =>
  database_manager.define(
    'user',
    // prettier-ignore
    {
      id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
      user_name: { type: DataTypes.STRING, unique: true, allowNull: false },
      password: { type: DataTypes.STRING, allowNull: false },
      player_name: { type: DataTypes.STRING, allowNull: false },
      role: { type: DataTypes.STRING, allowNull: false },
      validated_at: { type: DataTypes.DATE, allowNull: true },
      refresh_token: { type: DataTypes.TEXT, allowNull: true },
    },
    {
      tableName: 'users',
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at',
    }
  );
