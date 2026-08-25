const { createClient } = require('@libsql/client');
const { drizzle } = require('drizzle-orm/libsql');
const { sql } = require('drizzle-orm');

async function run() {
  const c = createClient({ url: 'file:local.db' });
  const db = drizzle(c);

  const t = 'users';
  const result = await db.run(sql`SELECT count(*) as count FROM ${sql.raw(t)}`);
  console.log(JSON.stringify(result, null, 2));
  console.log('Parsed count:', Number(result.rows[0]?.count || 0));
}
run();
