/* global db */
// Runs once when the MongoDB volume is first initialised (mongosh).
// Each service gets its own user that can only touch its own database.
const fs = require('fs');
const secret = (name) => fs.readFileSync(`/run/secrets/${name}`, 'utf8').trim();

db.getSiblingDB('secureshare').createUser({
  user: 'secureshare_api',
  pwd: secret('mongo_api_password'),
  roles: [{ role: 'readWrite', db: 'secureshare' }],
});

db.getSiblingDB('secureshare_authority').createUser({
  user: 'secureshare_authority',
  pwd: secret('mongo_authority_password'),
  roles: [{ role: 'readWrite', db: 'secureshare_authority' }],
});
