const { createClient } = require('@libsql/client');
const { drizzle } = require('drizzle-orm/libsql');
const { sql } = require('drizzle-orm');

async function run() {
  const c = createClient({ url: 'file:local.db' });
  const db = drizzle(c);
  console.log(typeof db.execute);
  if (typeof db.run === 'function') {
      const res = await db.all(sql`SELECT count(*) as count FROM users`);
      console.log('db.all:', res);
  }
}
run();
