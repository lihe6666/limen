//! Limen —— 基于 TUI 的 LLM 智能 WAF。
//! 阶段3:反向代理 + 规则引擎 + TUI 仪表盘。

mod config;
mod engine;
mod eval;
mod event;
mod learn;
mod proxy;
mod ratelimit;
mod state;
mod storage;
mod tui;

use std::io::IsTerminal;
use std::sync::Arc;

use anyhow::Context;
use config::Config;
use engine::{LlmAdjudicator, NgramClassifier, RuleEngine};
use proxy::{ProxyState, MAX_BODY_BYTES};
use state::Controls;
use storage::Storage;
use tokio::sync::{mpsc, Semaphore};

/// 同一 IP 累计拦截达到此值自动封禁。
const AUTO_BAN_THRESHOLD: u32 = 5;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // --help / -h: 打印帮助文档
    if args.len() > 1 {
        let first = args[1].as_str();
        if first == "--help" || first == "-h" {
            print_help(&args[0]);
            return Ok(());
        }
    }

    // `limen eval [样本目录]`:离线评测规则引擎,跑完即退出
    if std::env::args().nth(1).as_deref() == Some("eval") {
        return eval::run(std::env::args().skip(2).collect()).await;
    }
    // `limen learn [gaps.jsonl]`:离线规则蒸馏,跑完即退出
    if std::env::args().nth(1).as_deref() == Some("learn") {
        return learn::run(std::env::args().skip(2).collect()).await;
    }

    // 管理子命令:不需要完整启动 WAF
    if let Some(cmd) = std::env::args().nth(1).as_deref() {
        match cmd {
            "get" => return cmd_get(std::env::args().skip(2).collect()),
            "set" => return cmd_set(std::env::args().skip(2).collect()),
            _ => {} // 其他当作配置文件路径
        }
    }

    let config_path =
        std::env::args().nth(1).unwrap_or_else(|| "config.toml".to_string());
    let cfg = Config::load(&config_path)?;

    // TUI 会独占终端,日志必须落文件,否则会污染界面。
    let _log_guard = init_file_logging(&cfg.log_file);
    tracing::info!(listen = %cfg.listen, upstream = %cfg.upstream, "启动 Limen");

    let upstream = cfg.upstream.trim_end_matches('/').to_string();
    let mut body_limit = MAX_BODY_BYTES;
    if cfg.detection.max_body_bytes > 0 {
        body_limit = cfg.detection.max_body_bytes;
    }

    let client_builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none());
    let client_builder = if cfg.detection.upstream_timeout_secs > 0 {
        client_builder.timeout(std::time::Duration::from_secs(cfg.detection.upstream_timeout_secs))
    } else {
        client_builder
    };
    let client = client_builder
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

    // 存储层:SQLite 持久化(黑名单 + 直通白名单 + 审计日志)
    let storage: Option<Arc<Storage>> = if cfg.db_path.is_empty() {
        None
    } else {
        match Storage::open(&cfg.db_path) {
            Ok(s) => {
                let s = Arc::new(s);
                // 将 config.toml 中的直通路径写入存储层(去重)
                for p in &cfg.detection.bypass_paths {
                    let _ = s.add_bypass(p, "config.toml");
                }
                Some(s)
            }
            Err(e) => {
                tracing::error!(error = %e, path = %cfg.db_path, "SQLite 打开失败,降级为纯内存模式");
                None
            }
        }
    };

    // 重建 Controls:传入 Storage 引用(用于黑名单持久化)
    let controls = Arc::new(Controls::new(AUTO_BAN_THRESHOLD, storage.clone()));

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

    let llm_sem = Arc::new(Semaphore::new(32));

    let rate_limiter = if cfg.detection.rate_limit_rps > 0 {
        Some(Arc::new(ratelimit::RateLimiter::new(
            cfg.detection.rate_limit_rps,
            cfg.detection.rate_limit_burst,
        )))
    } else {
        None
    };

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
        llm_sem,
        storage: storage.clone(),
        body_limit,
        rate_limiter,
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
        // with_graceful_shutdown:收到关闭信号后 axum 停止接受新连接,等待在途请求处理完再退出
        if let Err(e) = serve.with_graceful_shutdown(shutdown_signal()).await {
            tracing::error!(error = %e, "HTTP 服务退出");
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

/// 优雅关闭信号:await 到 Ctrl-C 或 SIGTERM(Unix)任一即返回。
/// axum 的 with_graceful_shutdown 在收到信号后停止接受新连接,等待在途请求处理完再退出。
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await
            .expect("无法安装 Ctrl-C 信号处理器");
    };

    #[cfg(unix)]
    {
        let sigterm = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("无法安装 SIGTERM 信号处理器")
                .recv()
                .await;
        };
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm => {},
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }

    tracing::info!("收到关闭信号,优雅退出中");
}

/// 初始化落文件的日志(非阻塞)。返回的 guard 必须在 main 存活期间保留。
fn init_file_logging(log_file: &str) -> tracing_appender::non_blocking::WorkerGuard {
    let path = std::path::Path::new(log_file);
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "limen.log".to_string());

    // rolling::daily 按天切分日志,文件名自动追加日期后缀(如 limen.log.2026-07-10),
    // 避免日志文件无限增长。
    let appender = tracing_appender::rolling::daily(dir, file_name);
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

/// 执行 `limen get <subject>` 子命令。
fn cmd_get(args: Vec<String>) -> anyhow::Result<()> {
    match args.first().map(|s| s.as_str()) {
        Some("health") => cmd_get_health(),
        Some("bypass") => cmd_get_bypass(&args),
        Some("blacklist") => cmd_get_blacklist(&args),
        Some(other) => anyhow::bail!("未知 get 子命令: {other}。可用: health, bypass, blacklist"),
        None => anyhow::bail!("缺少 get 子命令。可用: health, bypass, blacklist"),
    }
}

/// `limen get health` — 检查 WAF 基本状态。
fn cmd_get_health() -> anyhow::Result<()> {
    let cfg = Config::load("config.toml")?;
    println!("limen 状态: ok");
    println!("  监听:       {}", cfg.listen);
    println!("  源站:       {}", cfg.upstream);
    println!("  模式:       {}", if cfg.headless { "headless" } else { "TUI" });
    println!("  配置文件:   config.toml");
    if cfg.db_path.is_empty() {
        println!("  数据库:     未配置(纯内存模式)");
    } else {
        match Storage::open(&cfg.db_path) {
            Ok(_) => println!("  数据库:     {} (正常)", cfg.db_path),
            Err(e) => println!("  数据库:     {} (异常: {e})", cfg.db_path),
        }
    }
    print!("  规则类别:   ");
    let all = [
        "SQLi", "XSS", "PathTraversal", "CommandInjection", "SSRF", "RCE",
        "SSTI", "XXE", "NoSQLi", "LDAPi", "CRLF", "InfoDisclosure", "Scanner",
    ];
    let enabled: Vec<&str> = all
        .iter()
        .filter(|c| !cfg.detection.disabled_categories.contains(&c.to_string()))
        .copied()
        .collect();
    println!("{} 类已启用", enabled.len());
    if cfg.llm.enabled {
        println!("  LLM 研判:   启用({}, {})", cfg.llm.provider, cfg.llm.model);
    } else {
        println!("  LLM 研判:   未启用");
    }
    if cfg.detection.ngram_model.is_some() {
        println!("  ngram:      已配置");
    }
    Ok(())
}

/// `limen get bypass` — 列出所有直通路径。
fn cmd_get_bypass(args: &[String]) -> anyhow::Result<()> {
    let db_path = args.get(1).map(|s| s.as_str()).unwrap_or("limen.db");
    let storage = Storage::open(db_path)?;
    let list = storage.list_bypass()?;
    if list.is_empty() {
        println!("直通白名单为空");
        return Ok(());
    }
    println!("直通白名单 ({} 条):", list.len());
    for bp in &list {
        println!("  {}  # {}", bp.pattern, bp.comment);
    }
    Ok(())
}

/// `limen get blacklist` — 列出所有封禁 IP。
fn cmd_get_blacklist(args: &[String]) -> anyhow::Result<()> {
    let db_path = args.get(1).map(|s| s.as_str()).unwrap_or("limen.db");
    let storage = Storage::open(db_path)?;
    let list = storage.list_blacklist()?;
    if list.is_empty() {
        println!("黑名单为空");
        return Ok(());
    }
    println!("黑名单 ({} 条):", list.len());
    for entry in &list {
        println!("  {:<20}  {}  ({})", entry.ip, entry.reason, entry.blocked_at);
    }
    Ok(())
}

/// 执行 `limen set <subject> <action> <value>` 子命令。
fn cmd_set(args: Vec<String>) -> anyhow::Result<()> {
    match args.first().map(|s| s.as_str()) {
        Some("bypass") => {
            let action = args.get(1).map(|s| s.as_str());
            let pattern = args.get(2).map(|s| s.as_str());
            let db_path = args.get(3).map(|s| s.as_str()).unwrap_or("limen.db");
            match (action, pattern) {
                (Some("add"), Some(p)) => {
                    let storage = Storage::open(db_path)?;
                    if storage.add_bypass(p, "cli")? {
                        println!("已添加直通路径: {p}");
                    } else {
                        println!("直通路径已存在: {p}");
                    }
                    Ok(())
                }
                (Some("remove"), Some(p)) => {
                    let storage = Storage::open(db_path)?;
                    if storage.remove_bypass(p)? {
                        println!("已移除直通路径: {p}");
                    } else {
                        println!("直通路径不存在: {p}");
                    }
                    Ok(())
                }
                _ => anyhow::bail!("用法: limen set bypass add|remove <路径> [数据库文件]"),
            }
        }
        Some(other) => anyhow::bail!("未知 set 子命令: {other}。可用: bypass"),
        None => anyhow::bail!("缺少 set 子命令。可用: bypass"),
    }
}

fn print_help(bin: &str) {
    let name = std::path::Path::new(bin)
        .file_name()
        .map(|s| s.to_string_lossy())
        .unwrap_or(std::borrow::Cow::Borrowed("limen"));
    eprintln!("{name} — LLM 增强型 Web 应用防火墙 (WAF)");
    eprintln!("");
    eprintln!("用法:");
    eprintln!("  {name}                        启动 WAF(TUI 或 headless)");
    eprintln!("  {name} <config.toml>           指定配置文件路径");
    eprintln!("  {name} eval [选项] [目录]      离线评测规则引擎");
    eprintln!("  {name} learn [选项] <文件>     规则蒸馏");
    eprintln!("  {name} get health              查看 WAF 健康状态");
    eprintln!("  {name} get bypass              列出直通白名单");
    eprintln!("  {name} get blacklist           列出黑名单 IP");
    eprintln!("  {name} set bypass add <路径>    添加直通路径");
    eprintln!("  {name} set bypass remove <路径> 删除直通路径");
    eprintln!("  {name} --help                  显示此帮助信息");
    eprintln!("");
    eprintln!("子命令:");
    eprintln!("  eval");
    eprintln!("    使用 BlazeHTTP 样本集量化规则引擎(及可选 LLM)的检出率/误报率。");
    eprintln!("    选项:");
    eprintln!("      --llm            同时测试 LLM 二级研判(需 config.toml 中配好 API key)");
    eprintln!("      <目录>            样本目录,默认 testdata/blazehttp");
    eprintln!("    输出:target/eval/ 下的漏报(missed_black.txt)与误报(fp_white.txt)明细");
    eprintln!("");
    eprintln!("  learn");
    eprintln!("    读缺口捕获 JSONL → LLM 提议候选规则 → 白样本误报闸门校验 → 输出候选。");
    eprintln!("    选项:");
    eprintln!("      --whites <目录>   白样本目录,默认 testdata/blazehttp");
    eprintln!("      <文件>            gaps.jsonl 路径,默认 gaps.jsonl");
    eprintln!("    输出:candidate_rules.txt(零误报候选,需人工审核后手工采纳)");
    eprintln!("");
    eprintln!("  get");
    eprintln!("    health             检查 WAF 状态:数据库连通性、配置摘要");
    eprintln!("    bypass             列出 SQLite 中所有直通白名单路径");
    eprintln!("    blacklist          列出 SQLite 中所有封禁 IP");
    eprintln!("");
    eprintln!("  set bypass");
    eprintln!("    add <路径>          添加直通路径(精确匹配或以 / 结尾做前缀匹配)");
    eprintln!("    remove <路径>       移除直通路径");
    eprintln!("");
    eprintln!("常用示例:");
    eprintln!("  {name}                                          # 默认配置启动");
    eprintln!("  {name} /etc/limen/config.toml                    # 指定配置");
    eprintln!("  {name} eval                                     # 规则引擎离线评测");
    eprintln!("  {name} eval --llm                               # 三级漏斗(含 LLM)评测");
    eprintln!("  {name} learn gaps.jsonl                         # 规则蒸馏");
    eprintln!("  {name} get health                               # 健康检查");
    eprintln!("  {name} get bypass                               # 查看直通路径");
    eprintln!("  {name} get blacklist                            # 查看黑名单");
    eprintln!("  {name} set bypass add /internal/                # 添加直通路径");
    eprintln!("");
    eprintln!("更多文档: README.md");
}
