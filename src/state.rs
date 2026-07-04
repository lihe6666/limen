//! 运行时共享控制状态:IP 黑名单 + 拦截/监控模式。
//! 由代理任务(读写)和 TUI 线程(读 + 键盘切换)共享,故用线程安全原语。
//! 约束:持锁期间不得 await,锁只做短暂读写。

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

pub struct Controls {
    /// 已封禁的 IP
    banned: RwLock<HashSet<IpAddr>>,
    /// 每个 IP 的累计拦截次数(用于自动封禁)
    block_counts: RwLock<HashMap<IpAddr, u32>>,
    /// true = 拦截生效;false = 仅监控(检测照跑,但一律放行)
    enforce: AtomicBool,
    /// 同一 IP 累计拦截达此值则自动封禁(0 表示不自动封禁)
    auto_ban_threshold: u32,
}

impl Controls {
    pub fn new(auto_ban_threshold: u32) -> Self {
        Self {
            banned: RwLock::new(HashSet::new()),
            block_counts: RwLock::new(HashMap::new()),
            enforce: AtomicBool::new(true),
            auto_ban_threshold,
        }
    }

    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        self.banned.read().unwrap().contains(ip)
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
            self.banned.write().unwrap().insert(ip);
            true
        } else {
            false
        }
    }

    /// 清空黑名单与计数,返回被解封的 IP 数。
    pub fn unban_all(&self) -> usize {
        let n = self.banned.read().unwrap().len();
        self.banned.write().unwrap().clear();
        self.block_counts.write().unwrap().clear();
        n
    }

    pub fn banned_count(&self) -> usize {
        self.banned.read().unwrap().len()
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
