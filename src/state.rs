//! 运行时共享控制状态:拦截/监控模式 + 自动封禁计数器。
//! IP 黑名单由 `storage::Storage` 统一管理(内存缓存 + SQLite 持久化),
//! 本模块只维护**自动封禁的计数器**和**拦截/监控模式开关**。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

use crate::storage::Storage;

pub struct Controls {
    /// 每个 IP 的累计拦截次数(用于自动封禁)
    block_counts: RwLock<HashMap<IpAddr, u32>>,
    /// true = 拦截生效;false = 仅监控(检测照跑,但一律放行)
    enforce: AtomicBool,
    /// 同一 IP 累计拦截达此值则自动封禁(0 表示不自动封禁)
    auto_ban_threshold: u32,
    /// 持久化存储层(黑名单读/写/清空均委托给它)
    storage: Option<std::sync::Arc<Storage>>,
}

impl Controls {
    pub fn new(auto_ban_threshold: u32, storage: Option<std::sync::Arc<Storage>>) -> Self {
        Self {
            block_counts: RwLock::new(HashMap::new()),
            enforce: AtomicBool::new(true),
            auto_ban_threshold,
            storage,
        }
    }

    /// 检查 IP 是否被封禁(委托 Storage,含内存缓存)。
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        match &self.storage {
            Some(s) => s.is_banned(&ip.to_string()),
            None => false,
        }
    }

    /// 记录一次针对某 IP 的拦截;若因此达到阈值则自动封禁,返回是否"本次新封禁"。
    pub fn record_block(&self, ip: IpAddr) -> bool {
        if self.auto_ban_threshold == 0 {
            return false;
        }
        let count = {
            let mut counts = self.block_counts.write().unwrap();
            let c = counts.entry(ip).or_insert(0);
            *c += 1;
            *c
        };
        if count >= self.auto_ban_threshold && !self.is_banned(&ip) {
            if let Some(ref s) = self.storage {
                let _ = s.add_blacklist(&ip.to_string(), "auto-ban");
            }
            true
        } else {
            false
        }
    }

    /// 清空黑名单与计数,返回被解封的 IP 数。
    pub fn unban_all(&self) -> usize {
        self.block_counts.write().unwrap().clear();
        match &self.storage {
            Some(s) => s.clear_blacklist().unwrap_or(0),
            None => 0,
        }
    }

    pub fn banned_count(&self) -> usize {
        match &self.storage {
            Some(s) => s.banned_count(),
            None => 0,
        }
    }

    pub fn enforce(&self) -> bool {
        self.enforce.load(Ordering::Relaxed)
    }

    /// 切换拦截/监控模式,返回切换后的 enforce 值。
    pub fn toggle_enforce(&self) -> bool {
        let new = !self.enforce.load(Ordering::Relaxed);
        self.enforce.store(new, Ordering::Relaxed);
        new
    }
}
