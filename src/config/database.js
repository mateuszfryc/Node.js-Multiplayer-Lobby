import bcrypt from 'bcrypt';
import fs from 'fs';
import path from 'path';
import * as sq from 'sequelize';
import { fileURLToPath } from 'url';
import * as uuid from 'uuid';
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
  console.log('Starting data seeding process...');
  for (const model of models) {
    const modelName = model.name; // Get the model's name
    const modelSeed = data[modelName]; // Fetch the corresponding seed data

    if (modelSeed) {
      console.log(`Found seed data for ${modelName}`);
      for (const seedEntry of modelSeed) {
        const existingData = await model.findOne({
          where: { email: seedEntry.email }, // Match existing data by unique field (e.g., email)
        });

        if (existingData) {
          console.log('Existing data: ', existingData.toJSON());
          // Check if the password needs to be updated
          const isPasswordHashed = existingData.password.startsWith('$2b$');
          if (!isPasswordHashed) {
            console.log(
              `Updating password for existing user: ${seedEntry.email}`
            );
            const hashedPassword = await bcrypt.hash(seedEntry.password, 10);
            await existingData.update({ password: hashedPassword });
          } else {
            console.log(`Password already hashed for user: ${seedEntry.email}`);
          }
          // Check if id is uuid v4
          const id = existingData.id;
          if (typeof id !== 'string' || id.length !== 36) {
            console.log(`Updating id for existing user: ${seedEntry.email}`);
            await existingData.update({ id: uuid.v4() });
          }
        } else {
          console.log(
            `Creating new entry for ${modelName}: ${seedEntry.email}`
          );
          // Hash the password before creating the new entry
          seedEntry.password = await bcrypt.hash(seedEntry.password, 10);
          await model.create(seedEntry);
        }
      }
    } else {
      console.log(`No seed data defined for ${modelName}, skipping.`);
    }
  }
  console.log('Data seeding completed.');
};

export const setupDb = async () => {
  if (db.client) return;

  const client = new sq.Sequelize(
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
