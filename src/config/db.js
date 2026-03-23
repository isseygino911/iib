import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

/**
 * MySQL connection pool.
 * Uses environment variables for all connection parameters.
 */
const pool = mysql.createPool({
  host:               process.env.DB_HOST     || 'localhost',
  user:               process.env.DB_USER     || 'root',
  password:           process.env.DB_PASSWORD || '',
  database:           process.env.DB_NAME     || 'ii_design',
  waitForConnections: true,
  connectionLimit:    10,
  queueLimit:         0,
  timezone:           '+00:00',
});

/**
 * Test the database connection on startup.
 * @returns {Promise<void>}
 */
export async function testConnection() {
  try {
    const conn = await pool.getConnection();
    console.log('[db] MySQL connected successfully');
    conn.release();
  } catch (err) {
    console.error('[db] MySQL connection failed:', err.message);
    process.exit(1);
  }
}

export default pool;
