import { DataTypes } from 'sequelize';

export const activationsSchema = (database_manager) =>
  database_manager.define(
    'activation',
    {
      user_id: { type: DataTypes.UUID, allowNull: false },
      token: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        allowNull: false,
      },
      expires_at: { type: DataTypes.DATE, allowNull: false },
    },
    {
      tableName: 'activations',
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at',
    }
  );
