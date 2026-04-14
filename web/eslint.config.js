import js from '@eslint/js'
import globals from 'globals'
import reactPlugin from 'eslint-plugin-react'
import reactHooksPlugin from 'eslint-plugin-react-hooks'

export default [
  // Ignore patterns
  {
    ignores: [
      'dist/**',
      'coverage/**',
      'node_modules/**',
      '*.min.js',
    ],
  },

  // Base JavaScript recommended rules
  js.configs.recommended,

  // React configuration
  {
    files: ['**/*.{js,jsx}'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.es2021,
      },
      parserOptions: {
        ecmaFeatures: {
          jsx: true,
        },
      },
    },
    plugins: {
      react: reactPlugin,
      'react-hooks': reactHooksPlugin,
    },
    settings: {
      react: {
        version: 'detect',
      },
    },
  rules: {
    // React recommended rules
    ...reactPlugin.configs.recommended.rules,
    ...reactPlugin.configs['jsx-runtime'].rules,

    // React Hooks rules
    ...reactHooksPlugin.configs.recommended.rules,

    // Customizations for this codebase
    'react/prop-types': 'off', // Not using PropTypes
    'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    
    // The react-hooks v7 plugin has very strict rules that flag legitimate patterns.
    // These are legitimate use cases:
    // - setState in effects for syncing local state with server data
    // - ref access during render for refs that don't affect rendering
    'react-hooks/set-state-in-effect': 'off',
    'react-hooks/refs': 'off',
  },
},

// Test files configuration
{
  files: ['**/*.test.{js,jsx}', '**/test/**/*.{js,jsx}'],
  languageOptions: {
    globals: {
      ...globals.vitest,
      ...globals.node,
    },
  },
},
]
