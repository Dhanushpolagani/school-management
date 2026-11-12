
require("dotenv").config();

const { Pool } = require("pg");

const databaseConfig = process.env.DATABASE_URL
  ? {
      // Neon PostgreSQL connection
      connectionString: process.env.DATABASE_URL,
      max: Number(process.env.DB_POOL_MAX || 5),
      connectionTimeoutMillis: 10000,
      idleTimeoutMillis: 30000,
    }
  : {
      // Local PostgreSQL connection
      host: process.env.DB_HOST || "127.0.0.1",
      port: Number(process.env.DB_PORT || 5432),
      database: process.env.DB_NAME || "school_erp",
      user: process.env.DB_USER || "postgres",
      password: process.env.DB_PASSWORD,
      max: Number(process.env.DB_POOL_MAX || 10),
      connectionTimeoutMillis: 5000,
      idleTimeoutMillis: 30000,
    };

const pool = new Pool(databaseConfig);

pool.on("error", (error) => {
  console.error("Unexpected database pool error:", error.message);
});

module.exports = pool;
module.exports.pool = pool;
