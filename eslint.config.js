import pluginJs from '@eslint/js';
import pluginImport from 'eslint-plugin-import';
import globals from 'globals';
import tseslint from 'typescript-eslint';

/** @type {import('eslint').Linter.Config[]} */
export default [
  ...pluginJs.configs.recommended,
  {
    files: ['**/*.{js}'],
    env: {
      node: true,
    },
    languageOptions: {
      sourceType: 'script',
      ...globals.node,
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
      '@typescript-eslint/ban-ts-comment': 'off',
    },
    plugins: {
      import: pluginImport,
    },
  },
  ...tseslint.configs.recommended,
];
