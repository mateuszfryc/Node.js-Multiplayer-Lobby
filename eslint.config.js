import pluginJs from '@eslint/js';
import pluginImport from 'eslint-plugin-import';
import globals from 'globals';
import tseslint from 'typescript-eslint';

/** @type {import('eslint').Linter.Config[]} */
export default [
  {
    files: ['**/*.{js,mjs,cjs,ts}'],
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
            ['#rooms', './src/modules/rooms'],
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
