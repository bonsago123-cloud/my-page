import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

const ddl = [
  `CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
    user_handle TEXT UNIQUE NOT NULL, created_at BIGINT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS passkeys (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name TEXT NOT NULL, public_key TEXT NOT NULL, counter BIGINT NOT NULL,
    transports TEXT NOT NULL, device_type TEXT, backed_up INTEGER NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL, last_used_at BIGINT)`,
  'CREATE INDEX IF NOT EXISTS ix_passkeys_user ON passkeys(user_id)',
  `CREATE TABLE IF NOT EXISTS challenges (
    ticket_hash TEXT PRIMARY KEY, kind TEXT NOT NULL, challenge TEXT NOT NULL,
    user_id TEXT, username TEXT, user_handle TEXT, passkey_name TEXT,
    created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL)`,
  'CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions(user_id)',
  `CREATE TABLE IF NOT EXISTS private_items (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    title TEXT NOT NULL, content TEXT NOT NULL, created_at BIGINT NOT NULL)`,
  'CREATE INDEX IF NOT EXISTS ix_private_user ON private_items(user_id)',
];

function sqliteAdapter(filename) {
  fs.mkdirSync(path.dirname(filename), { recursive: true });
  const sqlite = new DatabaseSync(filename);
  sqlite.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 3000;');
  // 한 SQLite 연결에 동시에 들어오는 HTTP 요청의 SQL을 직렬화합니다.
  // 트랜잭션 중 다른 요청의 SELECT/UPDATE가 끼어드는 것을 방지합니다.
  let queue = Promise.resolve();
  function serialize(fn) {
    const result = queue.then(fn);
    queue = result.catch(() => {});
    return result;
  }
  const unlocked = {
    kind: 'sqlite',
    async one(sql, p = []) { return sqlite.prepare(sql).get(...p) ?? null; },
    async all(sql, p = []) { return sqlite.prepare(sql).all(...p); },
    async run(sql, p = []) { const { changes } = sqlite.prepare(sql).run(...p); return changes; },
  };
  const q = {
    kind: 'sqlite',
    one: (sql, p = []) => serialize(() => unlocked.one(sql, p)),
    all: (sql, p = []) => serialize(() => unlocked.all(sql, p)),
    run: (sql, p = []) => serialize(() => unlocked.run(sql, p)),
    transaction: fn => serialize(async () => {
      sqlite.exec('BEGIN IMMEDIATE');
      try { const value = await fn(unlocked); sqlite.exec('COMMIT'); return value; }
      catch (e) { sqlite.exec('ROLLBACK'); throw e; }
    }),
    init: () => serialize(async () => { for (const statement of ddl) sqlite.exec(statement); }),
    close: () => serialize(async () => { sqlite.close(); }),
  };
  return q;
}

function postgresAdapter(connectionString) {
  // 동적 로드: 개발자는 Postgres 설정 없이 SQLite로 실행 가능
  return import('pg').then(({ default: pg }) => {
    const pool = new pg.Pool({ connectionString, max: 5 });
    const adapt = sql => {
      let n = 0;
      return sql.replace(/\?/g, () => `$${++n}`);
    };
    const queryer = conn => ({
      kind: 'postgres',
      async one(sql, p = []) { return (await conn.query(adapt(sql), p)).rows[0] ?? null; },
      async all(sql, p = []) { return (await conn.query(adapt(sql), p)).rows; },
      async run(sql, p = []) { return (await conn.query(adapt(sql), p)).rowCount; },
    });
    const root = queryer(pool);
    root.init = async () => { for (const statement of ddl) await pool.query(statement); };
    root.transaction = async fn => {
      const conn = await pool.connect();
      try {
        await conn.query('BEGIN');
        const value = await fn(queryer(conn));
        await conn.query('COMMIT');
        return value;
      } catch (e) { await conn.query('ROLLBACK'); throw e; }
      finally { conn.release(); }
    };
    root.close = async () => pool.end();
    return root;
  });
}

export async function openDatabase(config = process.env) {
  const db = config.DATABASE_URL
    ? await postgresAdapter(config.DATABASE_URL)
    : sqliteAdapter(config.SQLITE_PATH || path.resolve('.data', 'task8.sqlite'));
  await db.init();
  return db;
}
