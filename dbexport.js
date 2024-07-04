const { Pool } = require('pg');

// Create a new pool instance
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  //   password: process.env.DB_USER,
  port: 5432,
})

// Export the query method for passing queries to the pool
module.exports = {
  query: (text, params) => pool.query(text, params),
};
