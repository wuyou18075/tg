-- D1 schema (Worker 内置自动初始化，本文件仅作参考)
CREATE TABLE IF NOT EXISTS machines (
  machine_id TEXT PRIMARY KEY, hostname TEXT, interface TEXT,
  last_ts INTEGER, today_rx INTEGER, today_tx INTEGER,
  month_rx INTEGER, month_tx INTEGER, updated_at INTEGER,
  callback_url TEXT
);
CREATE TABLE IF NOT EXISTS snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT, machine_id TEXT NOT NULL,
  ts INTEGER NOT NULL, today_rx INTEGER, today_tx INTEGER,
  month_rx INTEGER, month_tx INTEGER
);
CREATE INDEX IF NOT EXISTS idx_snap_mid_ts ON snapshots(machine_id, ts);
CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS vps_tokens (
  machine_id TEXT PRIMARY KEY, token TEXT NOT NULL, created_at INTEGER
);
