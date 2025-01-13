import fs from 'fs';
import path from 'path';
import * as Sequelize from 'sequelize';
import { fileURLToPath } from 'url';
import { data } from './seed.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const db = {
  client: undefined,
};

import { pathToFileURL } from 'url';

const loadModels = async (baseDir, client) => {
  const searchModelsDir = async (dir) => {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const entryPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (entry.name === 'models') {
          // If a "models" directory is found, load all models inside it
          for (const file of fs.readdirSync(entryPath)) {
            if (file.endsWith('.js')) {
              // Process only .js files
              try {
                const modelUrl = pathToFileURL(path.join(entryPath, file)).href;
                const model = (await import(modelUrl)).default(client);
                client.models[model.name] = model;
                db[model.name] = model;
                console.log(`Loaded model: ${model.name}`);
              } catch (error) {
                console.error(`Error loading model file: ${file}`, error);
              }
            }
          }
        } else {
          // Recursively search subdirectories
          await searchModelsDir(entryPath);
        }
      }
    }
  };

  await searchModelsDir(baseDir); // Start searching from the baseDir
};

const seedData = async (models) => {
  for (const model of models) {
    const modelName = model.name; // Get the model's name
    const modelSeed = data[modelName]; // Fetch the corresponding seed data

    if (modelSeed) {
      // Check if data already exists
      const existingData = await model.findOne();
      if (!existingData) {
        // Seed the data
        await model.bulkCreate(modelSeed);
        console.log(`Seeded data for ${modelName}`);
      } else {
        console.log(`Data already exists for ${modelName}`);
      }
    } else {
      console.log(`No seed data defined for ${modelName}`);
    }
  }
};

export const setupDb = async () => {
  if (db.client) return;

  const client = new Sequelize.Sequelize(
    process.env.DB_NAME,
    process.env.DB_USER,
    process.env.DB_PASSWORD,
    {
      host: process.env.DB_HOST,
      dialect: 'postgres', // Dialect for PostgreSQL
    }
  );

  try {
    await client.authenticate();
    await loadModels(path.join(__dirname, '..'), client);
    db.client = client;
    await client.sync({ alter: true });
    console.log('Database connection has been established successfully.');
    seedData(Object.values(client.models));
  } catch (error) {
    console.error('Unable to connect to the database:', error);
  }
};
