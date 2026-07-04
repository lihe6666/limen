//! TUI 仪表盘:实时展示流量、拦截、统计。
//! 在独立线程里跑同步渲染循环:从 mpsc 拉取代理事件 → 更新状态 → 绘制 → 轮询键盘。

use std::collections::VecDeque;
use std::io::{self, Stdout};
use std::sync::Arc;
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame, Terminal,
};
use tokio::sync::mpsc;

use crate::event::{Action, WafEvent};
use crate::state::Controls;

/// 保留的最近事件条数。
const MAX_EVENTS: usize = 500;
/// 每帧最多从 channel 拉取的事件数(防止爆发流量卡住渲染)。
const DRAIN_PER_FRAME: usize = 512;

struct AppState {
    listen: String,
    upstream: String,
    controls: Arc<Controls>,
    events: VecDeque<WafEvent>, // 队首为最新
    total: u64,
    allowed: u64,
    suspicious: u64,
    blocked: u64,
}

impl AppState {
    fn new(listen: String, upstream: String, controls: Arc<Controls>) -> Self {
        Self {
            listen,
            upstream,
            controls,
            events: VecDeque::with_capacity(MAX_EVENTS),
            total: 0,
            allowed: 0,
            suspicious: 0,
            blocked: 0,
        }
    }

    fn push(&mut self, ev: WafEvent) {
        self.total += 1;
        match ev.action {
            Action::Allowed => self.allowed += 1,
            Action::Suspicious => self.suspicious += 1,
            Action::Blocked => self.blocked += 1,
        }
        self.events.push_front(ev);
        if self.events.len() > MAX_EVENTS {
            self.events.pop_back();
        }
    }
}

/// TUI 主循环(阻塞)。q/Esc/Ctrl-C 退出;m 切换拦截/监控;u 清空黑名单。
pub fn run(
    mut rx: mpsc::Receiver<WafEvent>,
    listen: String,
    upstream: String,
    controls: Arc<Controls>,
) -> io::Result<()> {
    let mut terminal = setup_terminal()?;
    let mut app = AppState::new(listen, upstream, controls);

    let result = loop {
        // 1) 拉取事件
        for _ in 0..DRAIN_PER_FRAME {
            match rx.try_recv() {
                Ok(ev) => app.push(ev),
                Err(_) => break,
            }
        }

        // 2) 绘制
        if let Err(e) = terminal.draw(|f| ui(f, &app)) {
            break Err(e);
        }

        // 3) 轮询键盘(200ms 超时 → 约 5fps 刷新且输入不迟钝)
        match event::poll(Duration::from_millis(200)) {
            Ok(true) => match event::read() {
                Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => {
                    let quit = matches!(k.code, KeyCode::Char('q') | KeyCode::Esc)
                        || (k.code == KeyCode::Char('c')
                            && k.modifiers.contains(KeyModifiers::CONTROL));
                    if quit {
                        break Ok(());
                    }
                    match k.code {
                        KeyCode::Char('m') => {
                            app.controls.toggle_enforce();
                        }
                        KeyCode::Char('u') => {
                            app.controls.unban_all();
                        }
                        _ => {}
                    }
                }
                Ok(_) => {}
                Err(e) => break Err(e),
            },
            Ok(false) => {}
            Err(e) => break Err(e),
        }
    };

    restore_terminal(&mut terminal)?;
    result
}

fn setup_terminal() -> io::Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(stdout))
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()
}

fn ui(f: &mut Frame, app: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // 统计
            Constraint::Min(0),    // 流量表
            Constraint::Length(1), // 底部提示
        ])
        .split(f.area());

    render_stats(f, chunks[0], app);
    render_table(f, chunks[1], app);
    render_footer(f, chunks[2]);
}

fn render_stats(f: &mut Frame, area: Rect, app: &AppState) {
    let line1 = Line::from(vec![
        Span::styled("Limen", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("  监听 "),
        Span::styled(&app.listen, Style::default().fg(Color::White)),
        Span::raw("  →  源站 "),
        Span::styled(&app.upstream, Style::default().fg(Color::White)),
    ]);
    let line2 = Line::from(vec![
        Span::raw("总计 "),
        Span::styled(app.total.to_string(), Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        Span::styled(format!("放行 {}", app.allowed), Style::default().fg(Color::Green)),
        Span::raw("   "),
        Span::styled(format!("可疑 {}", app.suspicious), Style::default().fg(Color::Yellow)),
        Span::raw("   "),
        Span::styled(format!("拦截 {}", app.blocked), Style::default().fg(Color::Red)),
    ]);

    let enforce = app.controls.enforce();
    let (mode_text, mode_color) = if enforce {
        ("ENFORCE(拦截生效)", Color::Green)
    } else {
        ("MONITOR(仅监控)", Color::Yellow)
    };
    let line3 = Line::from(vec![
        Span::raw("模式 "),
        Span::styled(mode_text, Style::default().fg(mode_color).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        Span::styled(
            format!("已封禁 IP {}", app.controls.banned_count()),
            Style::default().fg(Color::Magenta),
        ),
    ]);

    let p = Paragraph::new(vec![line1, line2, line3]).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" 状态 "),
    );
    f.render_widget(p, area);
}

fn render_table(f: &mut Frame, area: Rect, app: &AppState) {
    let header = Row::new(vec![
        Cell::from("时间"),
        Cell::from("客户端"),
        Cell::from("方法"),
        Cell::from("路径"),
        Cell::from("动作"),
        Cell::from("分数"),
        Cell::from("状态"),
        Cell::from("详情"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Gray));

    // 可见行数取决于表格高度(减去边框和表头)
    let capacity = area.height.saturating_sub(3) as usize;
    let rows = app.events.iter().take(capacity).map(|ev| {
        let color = match ev.action {
            Action::Allowed => Color::Green,
            Action::Suspicious => Color::Yellow,
            Action::Blocked => Color::Red,
        };
        let status = ev.status.map(|s| s.to_string()).unwrap_or_else(|| "-".into());
        let detail = ev
            .threat
            .as_ref()
            .map(|t| format!("[{}] {}", t, ev.detail))
            .unwrap_or_else(|| ev.detail.clone());
        Row::new(vec![
            Cell::from(ev.time.clone()),
            Cell::from(ev.client_ip.clone()),
            Cell::from(ev.method.clone()),
            Cell::from(ev.path.clone()),
            Cell::from(ev.action.label()).style(Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Cell::from(ev.score.to_string()),
            Cell::from(status),
            Cell::from(detail),
        ])
        .style(Style::default().fg(color))
    });

    let widths = [
        Constraint::Length(8),
        Constraint::Length(16),
        Constraint::Length(6),
        Constraint::Fill(2),
        Constraint::Length(8),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Fill(3),
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" 实时流量(最新在上) "),
    );
    f.render_widget(table, area);
}

fn render_footer(f: &mut Frame, area: Rect) {
    let key = |k: &str| Span::styled(format!(" {k} "), Style::default().fg(Color::Black).bg(Color::Cyan));
    let hint = Line::from(vec![
        key("q/Esc"),
        Span::raw(" 退出   "),
        key("m"),
        Span::raw(" 切换拦截/监控   "),
        key("u"),
        Span::raw(" 清空黑名单 "),
    ]);
    f.render_widget(Paragraph::new(hint).dim(), area);
}
