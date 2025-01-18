import pluginJs from '@eslint/js';
import pluginImport from 'eslint-plugin-import';
import globals from 'globals';
import tseslint from 'typescript-eslint';

/** @type {import('eslint').Linter.Config[]} */
export default [
  {
    files: ['**/*.{js}'],
    languageOptions: {
      globals: globals.node,
    },
    settings: {
      'import/resolver': {
        alias: {
          map: [
            ['#utils', './src/utils'],
            ['#config', './src/config'],
            ['#auth', './src/modules/auth'],
            ['#persistence', './src/modules/persistence'],
            ['#users', './src/modules/users'],
            ['#games', './src/modules/games'],
          ],
          extensions: ['.js'],
        },
      },
    },
    rules: {
      'import/no-unresolved': 'error',
    },
    plugins: {
      import: pluginImport,
    },
  },
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
];
