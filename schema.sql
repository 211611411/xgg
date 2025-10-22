-- 用户表
CREATE TABLE IF NOT EXISTS users (
    qq TEXT PRIMARY KEY,
    nickname TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_login TEXT NOT NULL,
    online INTEGER DEFAULT 0,
    last_message_time TEXT,
    register_ip TEXT,
    daily_message_count INTEGER DEFAULT 0,
    last_message_date TEXT
);

-- 消息表
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    qq TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (qq) REFERENCES users(qq)
);

-- IP限制表
CREATE TABLE IF NOT EXISTS ip_limits (
    ip TEXT PRIMARY KEY,
    register_count INTEGER DEFAULT 0,
    last_register_date TEXT,
    created_at TEXT NOT NULL
);

-- 创建索引以优化查询
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login);
CREATE INDEX IF NOT EXISTS idx_messages_qq ON messages(qq);
CREATE INDEX IF NOT EXISTS idx_ip_limits_date ON ip_limits(last_register_date);
CREATE INDEX IF NOT EXISTS idx_users_last_message ON users(last_message_time);