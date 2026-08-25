const { drizzle } = require('drizzle-orm/libsql');
const { createClient } = require('@libsql/client');
const client = createClient({ url: 'file:local.db' });
const db = drizzle(client);
console.log('execute exists?', typeof db.execute);
