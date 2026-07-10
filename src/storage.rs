//! SQLite 持久化存储层。
//!
//! 三张表:
//! - `bypass_paths` — 直通白名单,跳过全部三级检测
//! - `blacklist`    — IP 黑名单,封禁 IP 直接 403
//! - `audit_log`    — 请求审计日志(未来扩展)
//!
//! 热路径(每个请求的 is_banned / is_bypass)走内存缓存,
//! SQLite 作为持久化源,启动时全量加载,变更时写透(write-through)。

#![allow(dead_code)]

use std::collections::HashSet;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::Connection;

/// 直通红名单条目。
#[derive(Debug, Clone)]
pub struct BypassPath {
    pub pattern: String,
    pub comment: String,
    pub created_at: String,
}

/// 黑名单条目。
#[derive(Debug, Clone)]
pub struct BlacklistEntry {
    pub ip: String,
    pub reason: String,
    pub blocked_at: String,
}

/// 存储层:SQLite + 内存缓存。
pub struct Storage {
    conn: Mutex<Connection>,
    /// 热路径缓存:已封禁 IP 集合
    banned: Mutex<HashSet<String>>,
    /// 热路径缓存:直通路径集合(精确匹配和前缀匹配分开存)
    bypass_exact: Mutex<HashSet<String>>,
    bypass_prefix: Mutex<Vec<String>>,
}

impl Storage {
    /// 打开(或创建)数据库文件,执行建表迁移。
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path.as_ref())
            .with_context(|| format!("打开数据库 {:?} 失败", path.as_ref()))?;

        // 启用 WAL 模式:读不阻塞写,适应当前单进程架构
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA busy_timeout=5000;",
        )?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bypass_paths (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern     TEXT NOT NULL UNIQUE,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                comment     TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS blacklist (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT NOT NULL UNIQUE,
                reason      TEXT NOT NULL DEFAULT '',
                blocked_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                time        TEXT NOT NULL,
                client_ip   TEXT NOT NULL,
                method      TEXT NOT NULL,
                path        TEXT NOT NULL,
                action      TEXT NOT NULL,
                score       INTEGER NOT NULL DEFAULT 0,
                threat      TEXT,
                status      INTEGER,
                detail      TEXT NOT NULL DEFAULT '',
                tier        TEXT NOT NULL DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON blacklist(ip);
            CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(time);",
        )?;

        // 加载内存缓存
        let banned: HashSet<String> = {
            let mut stmt = conn.prepare("SELECT ip FROM blacklist")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            rows.filter_map(|r| r.ok()).collect()
        };

        let (exact, prefix): (HashSet<String>, Vec<String>) = {
            let mut stmt = conn.prepare("SELECT pattern FROM bypass_paths")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            let patterns: Vec<String> = rows.filter_map(|r| r.ok()).collect();
            let mut ex = HashSet::new();
            let mut pr = Vec::new();
            for p in patterns {
                if p.ends_with('/') {
                    pr.push(p);
                } else {
                    ex.insert(p);
                }
            }
            (ex, pr)
        };

        tracing::info!(
            "存储层就绪: {} 条黑名单, {} 条直通路径",
            banned.len(),
            exact.len() + prefix.len()
        );

        Ok(Self {
            conn: Mutex::new(conn),
            banned: Mutex::new(banned),
            bypass_exact: Mutex::new(exact),
            bypass_prefix: Mutex::new(prefix),
        })
    }

    // ── 热路径查询(纯内存) ─────────────────────────────────────

    /// 检查 IP 是否在黑名单中。
    pub fn is_banned(&self, ip: &str) -> bool {
        self.banned.lock().unwrap().contains(ip)
    }

    /// 检查路径是否在直通白名单中。
    pub fn is_bypass(&self, path: &str) -> bool {
        if self.bypass_exact.lock().unwrap().contains(path) {
            return true;
        }
        for prefix in self.bypass_prefix.lock().unwrap().iter() {
            if path.starts_with(prefix.as_str()) {
                return true;
            }
        }
        false
    }

    /// 封禁 IP 数(用于 TUI 显示)。
    pub fn banned_count(&self) -> usize {
        self.banned.lock().unwrap().len()
    }

    // ── 黑名单管理(写透) ───────────────────────────────────────

    /// 封禁一个 IP,返回是否新增(true=新封禁,false=已在黑名单中)。
    pub fn add_blacklist(&self, ip: &str, reason: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute(
            "INSERT OR IGNORE INTO blacklist (ip, reason) VALUES (?1, ?2)",
            rusqlite::params![ip, reason],
        )?;
        if affected > 0 {
            self.banned.lock().unwrap().insert(ip.to_string());
            tracing::info!(%ip, %reason, "IP 已加入黑名单");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// 从黑名单移除一个 IP。
    pub fn remove_blacklist(&self, ip: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute("DELETE FROM blacklist WHERE ip = ?1", rusqlite::params![ip])?;
        if affected > 0 {
            self.banned.lock().unwrap().remove(ip);
            tracing::info!(%ip, "IP 已从黑名单移除");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// 清空黑名单,返回清空的条目数。
    pub fn clear_blacklist(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count = conn.query_row("SELECT COUNT(*) FROM blacklist", [], |r| r.get::<_, usize>(0))?;
        conn.execute("DELETE FROM blacklist", [])?;
        self.banned.lock().unwrap().clear();
        tracing::info!(count, "黑名单已清空");
        Ok(count)
    }

    /// 列出全部黑名单条目。
    pub fn list_blacklist(&self) -> Result<Vec<BlacklistEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ip, reason, blocked_at FROM blacklist ORDER BY blocked_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(BlacklistEntry {
                ip: row.get(0)?,
                reason: row.get(1)?,
                blocked_at: row.get(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    // ── 直通白名单管理(写透) ───────────────────────────────────

    /// 添加一条直通路径。
    pub fn add_bypass(&self, pattern: &str, comment: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute(
            "INSERT OR IGNORE INTO bypass_paths (pattern, comment) VALUES (?1, ?2)",
            rusqlite::params![pattern, comment],
        )?;
        if affected > 0 {
            if pattern.ends_with('/') {
                self.bypass_prefix.lock().unwrap().push(pattern.to_string());
            } else {
                self.bypass_exact.lock().unwrap().insert(pattern.to_string());
            }
            tracing::info!(%pattern, "直通路径已添加");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// 删除一条直通路径。
    pub fn remove_bypass(&self, pattern: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute(
            "DELETE FROM bypass_paths WHERE pattern = ?1",
            rusqlite::params![pattern],
        )?;
        if affected > 0 {
            if pattern.ends_with('/') {
                self.bypass_prefix.lock().unwrap().retain(|p| p != pattern);
            } else {
                self.bypass_exact.lock().unwrap().remove(pattern);
            }
            tracing::info!(%pattern, "直通路径已移除");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// 列出全部直通路径。
    pub fn list_bypass(&self) -> Result<Vec<BypassPath>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT pattern, comment, created_at FROM bypass_paths ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(BypassPath {
                pattern: row.get(0)?,
                comment: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    // ── 审计日志 ──────────────────────────────────────────────

    /// 追加一条请求审计日志(写透)。
    pub fn append_audit_log(
        &self,
        time: &str,
        client_ip: &str,
        method: &str,
        path: &str,
        action: &str,
        score: u32,
        threat: Option<&str>,
        status: Option<u16>,
        detail: &str,
        tier: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_log (time, client_ip, method, path, action, score, threat, status, detail, tier)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                time, client_ip, method, path, action, score, threat, status, detail, tier
            ],
        )?;
        Ok(())
    }
}
