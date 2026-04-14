## Linting

This project uses ESLint for code quality checks.

### Available Scripts

- `npm run lint` - Check for linting errors
- `npm run lint:fix` - Auto-fix safe issues

### IDE Integration

For the best experience, install the ESLint extension in your editor:

- VS Code: [ESLint Extension](https://marketplace.visualstudio.com/items?itemName=dbaeumer.vscode-eslint)

### Configuration

The ESLint configuration is in `eslint.config.js` using the flat config format (ESLint 9+).

Key rules enabled:

- `eslint:recommended` - Baseline JavaScript best practices
- `plugin:react/recommended` - React-specific rules
- `plugin:react-hooks/recommended` - Hooks dependency rules
