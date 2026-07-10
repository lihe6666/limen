//! 令牌桶 per-IP 限流器,用于防御 CC / HTTP flood 攻击。
//! 使用 moka::future::Cache 做有界 per-IP 桶存储,TTL 自动淘汰空闲 IP 防内存无限增长。

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use moka::future::Cache;

struct TokenBucket {
    tokens: f64,
    last: Instant,
}

pub struct RateLimiter {
    buckets: Cache<IpAddr, Arc<Mutex<TokenBucket>>>,
    rps: f64,
    burst: f64,
}

impl RateLimiter {
    /// 新建限流器。
    /// - `rps`:每秒补充令牌数(稳态速率)
    /// - `burst`:桶容量(允许的突发量),0 则默认取 `rps * 2`
    pub fn new(rps: u32, burst: u32) -> Self {
        let burst = if burst == 0 {
            (rps.max(1) * 2) as f64
        } else {
            burst as f64
        };
        // 有界:最多缓存 10 万个活跃 IP 的桶,空闲 60s 自动淘汰
        let buckets = Cache::builder()
            .max_capacity(100_000)
            .time_to_idle(std::time::Duration::from_secs(60))
            .build();
        Self {
            buckets,
            rps: rps as f64,
            burst,
        }
    }

    /// 对给定 IP 尝试消耗 1 个令牌。
    /// 返回 `true` = 放行,`false` = 超限(应返回 429)。
    /// 令牌桶:按流逝时间补充令牌,消耗 1 个。
    pub async fn allow(&self, ip: IpAddr) -> bool {
        let bucket = self
            .buckets
            .get_with(ip, async move {
                Arc::new(Mutex::new(TokenBucket {
                    tokens: self.burst,
                    last: Instant::now(),
                }))
            })
            .await;
        let mut b = bucket.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.last = now;
        b.tokens = (b.tokens + elapsed * self.rps).min(self.burst);
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allow_within_burst() {
        // rps=10, burst=5,桶初始满 5 个令牌
        let rl = RateLimiter::new(10, 5);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..5 {
            assert!(rl.allow(ip).await, "桶内应该允许放行");
        }
    }

    #[tokio::test]
    async fn blocks_over_burst() {
        let rl = RateLimiter::new(10, 5);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        // 前 5 次放行
        for _ in 0..5 {
            assert!(rl.allow(ip).await);
        }
        // 第 6 次(未过时间)应该被限
        assert!(!rl.allow(ip).await, "超过突发量应被限");
    }
}
