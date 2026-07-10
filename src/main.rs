//! Limen —— 基于 TUI 的 LLM 智能 WAF。
//! 阶段3:反向代理 + 规则引擎 + TUI 仪表盘。

mod config;
mod engine;
mod eval;
mod event;
mod learn;
mod proxy;
mod state;
mod tui;

use std::io::IsTerminal;
use std::sync::Arc;

use anyhow::Context;
use config::Config;
use engine::{LlmAdjudicator, NgramClassifier, RuleEngine};
use proxy::ProxyState;
use state::Controls;
use tokio::sync::mpsc;

/// 同一 IP 累计拦截达到此值自动封禁。
const AUTO_BAN_THRESHOLD: u32 = 5;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `limen eval [样本目录]`:离线评测规则引擎,跑完即退出
    if std::env::args().nth(1).as_deref() == Some("eval") {
        return eval::run(std::env::args().skip(2).collect()).await;
    }
    // `limen learn [gaps.jsonl]`:离线规则蒸馏,跑完即退出
    if std::env::args().nth(1).as_deref() == Some("learn") {
        return learn::run(std::env::args().skip(2).collect()).await;
    }

    let config_path =
        std::env::args().nth(1).unwrap_or_else(|| "config.toml".to_string());
    let cfg = Config::load(&config_path)?;

    // TUI 会独占终端,日志必须落文件,否则会污染界面。
    let _log_guard = init_file_logging(&cfg.log_file);
    tracing::info!(listen = %cfg.listen, upstream = %cfg.upstream, "启动 Limen");

    let upstream = cfg.upstream.trim_end_matches('/').to_string();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("构建 HTTP 客户端失败")?;

    // 代理 → TUI 的事件通道
    let (tx, rx) = mpsc::channel(1024);

    // 二级 LLM 研判(可选)。启用失败不致命:降级为仅规则引擎。
    let llm = if cfg.llm.enabled {
        match LlmAdjudicator::from_config(&cfg.llm, client.clone()) {
            Ok(a) => {
                tracing::info!(provider = %cfg.llm.provider, model = %cfg.llm.model, "LLM 研判已启用");
                Some(Arc::new(a))
            }
            Err(e) => {
                tracing::error!(error = %e, "LLM 研判初始化失败,降级为仅规则引擎");
                None
            }
        }
    } else {
        None
    };

    // ngram 分类器(可选)。加载失败降级为不启用。
    let ngram = match &cfg.detection.ngram_model {
        Some(path) => match NgramClassifier::load(path) {
            Ok(c) => {
                tracing::info!(path = %path, "ngram 分类器已加载");
                Some(c)
            }
            Err(e) => {
                tracing::error!(error = %e, path = %path, "ngram 分类器加载失败,降级为不启用");
                None
            }
        },
        None => None,
    };

    let controls = Arc::new(Controls::new(AUTO_BAN_THRESHOLD));

    let trusted_proxies: Vec<std::net::IpAddr> = cfg
        .trusted_proxies
        .iter()
        .filter_map(|s| match s.parse::<std::net::IpAddr>() {
            Ok(ip) => Some(ip),
            Err(e) => {
                tracing::warn!(%s, error = %e, "trusted_proxies 解析失败,跳过");
                None
            }
        })
        .collect();

    let state = Arc::new(ProxyState {
        client,
        upstream: upstream.clone(),
        engine: RuleEngine::new_filtered(&cfg.detection.disabled_categories),
        block_threshold: cfg.detection.block_threshold,
        suspicious_threshold: cfg.detection.suspicious_threshold,
        llm,
        ngram,
        ngram_threshold: cfg.detection.ngram_threshold,
        controls: controls.clone(),
        tx,
        gap_log: cfg.detection.gap_log.clone(),
        trusted_proxies,
        real_ip_header: cfg.real_ip_header.clone(),
    });
    let app = proxy::router(state);

    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("无法监听 {}", cfg.listen))?;
    tracing::info!("WAF 已就绪,监听 {}", cfg.listen);

    let serve = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    );

    // 无 TTY(服务器/容器)时 TUI 无法运行;显式配置或自动检测到非终端 → headless。
    // 否则代理会随 TUI 线程一起退出,无法作为守护进程存活。
    let headless = cfg.headless || !std::io::stdout().is_terminal();

    if headless {
        tracing::info!("以 headless(无界面)模式运行,仅反向代理");
        // 无 TUI 消费事件流:起一个任务把通道抽干,避免有界通道占满。
        tokio::spawn(async move {
            let mut rx = rx;
            while rx.recv().await.is_some() {}
        });
        // 前台驻留:代理服务退出或收到 Ctrl-C 才结束。
        tokio::select! {
            r = serve => {
                if let Err(e) = r {
                    tracing::error!(error = %e, "HTTP 服务退出");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("收到 Ctrl-C,退出");
            }
        }
    } else {
        // 交互模式:代理在后台任务跑,TUI 在独立 OS 线程渲染;TUI 返回即退出程序。
        tokio::spawn(async move {
            if let Err(e) = serve.await {
                tracing::error!(error = %e, "HTTP 服务退出");
            }
        });
        let listen = cfg.listen.clone();
        let tui_handle = std::thread::spawn(move || tui::run(rx, listen, upstream, controls));
        match tui_handle.join() {
            Ok(Ok(())) => tracing::info!("TUI 正常退出"),
            Ok(Err(e)) => tracing::error!(error = %e, "TUI 异常"),
            Err(_) => tracing::error!("TUI 线程 panic"),
        }
    }

    Ok(())
}

/// 初始化落文件的日志(非阻塞)。返回的 guard 必须在 main 存活期间保留。
fn init_file_logging(log_file: &str) -> tracing_appender::non_blocking::WorkerGuard {
    let path = std::path::Path::new(log_file);
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "limen.log".to_string());

    let appender = tracing_appender::rolling::never(dir, file_name);
    let (non_blocking, guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_writer(non_blocking)
        .with_ansi(false)
        .init();
    guard
}
