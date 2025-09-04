// import dotenv from "dotenv";
import 'dotenv/config'; // automatically loads .env

import pkg from "pg";
const { Client } = pkg;

const db = new Client({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

db.connect()
  .then(() => console.log("✅ Database connected"))
  .catch((err) => console.error("❌ Database connection error:", err));

export default db;

