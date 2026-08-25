const express = require('express');
const { createClient } = require('@libsql/client');
const { drizzle } = require('drizzle-orm/libsql');
const { sql } = require('drizzle-orm');

const client = createClient({ url: 'file:local.db' });
const db = drizzle(client);
const app = express();
app.get('/test', async (req, res) => {
    try {
      const tables = ["users", "reports"];
      const counts = await Promise.all(tables.map(async (t) => {
        // Use client.execute instead of db.execute because db.execute fails
        const result = await db.run(sql`SELECT count(*) as count FROM ${sql.raw(t)}`);
        return { name: t, count: Number(result.rows[0]?.count || 0) };
      }));
      res.json(counts);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: err.message });
    }
});
const server = app.listen(3001, async () => {
    const fetch = (await import('node-fetch')).default;
    const res = await fetch('http://localhost:3001/test');
    console.log(await res.json());
    server.close();
});
