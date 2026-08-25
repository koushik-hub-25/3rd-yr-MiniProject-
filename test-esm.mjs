import { drizzle } from "drizzle-orm/libsql";
import { createClient } from "@libsql/client";
import { sql } from "drizzle-orm";

const c = createClient({ url: 'file:local.db' });
const db = drizzle(c);

const result = await db.run(sql`SELECT count(*) as count FROM users`);
console.log(JSON.stringify(result));
