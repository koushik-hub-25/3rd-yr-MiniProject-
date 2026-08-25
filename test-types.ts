import { drizzle } from "drizzle-orm/libsql";
import { createClient } from "@libsql/client";
import { sql } from "drizzle-orm";

async function run() {
  const c = createClient({ url: 'file:local.db' });
  const db = drizzle(c);
  const result = await db.run(sql`SELECT * FROM users`);
  console.log(result.rows);
}
