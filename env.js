// env.js — Custom .env file loader (no external packages)
// Reads key=value pairs from .env into process.env

const fs = require('fs');
const path = require('path');

/**
 * Loads environment variables from a .env file into process.env.
 * Skips comments (#) and blank lines. Does not override existing env vars.
 */
function loadEnv() {
  const envPath = path.join(__dirname, '.env');

  if (!fs.existsSync(envPath)) {
    console.warn('⚠️  No .env file found. Using system environment variables only.');
    return;
  }

  const content = fs.readFileSync(envPath, 'utf-8');
  const lines = content.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();

    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('#')) continue;

    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;

    const key = trimmed.substring(0, eqIndex).trim();
    let value = trimmed.substring(eqIndex + 1).trim();

    // Remove surrounding quotes if present
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }

    // Don't override existing environment variables
    if (!(key in process.env)) {
      process.env[key] = value;
    }
  }
}

loadEnv();
