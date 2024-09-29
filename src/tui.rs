use crate::{
    state::State,
    traffic::{Body, Traffic, TrafficHead},
};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    prelude::*,
    style::palette::material::GRAY,
    text::{Line, Span},
    widgets::{Block, Cell, Paragraph, Row, Table, TableState, Wrap},
};
use std::{
    io,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use unicode_width::UnicodeWidthStr;

const TICK_INTERVAL: u64 = 250;
const LARGE_WIDTH: u16 = 100;
const SELECTED_STYLE: Style = Style::new().bg(GRAY.c800).add_modifier(Modifier::BOLD);

pub async fn run(state: Arc<State>, addr: &str) -> Result<()> {
    let state_cloned = state.clone();
    let (message_tx, message_rx) = mpsc::unbounded_channel();
    let message_tx_cloned = message_tx.clone();
    tokio::spawn(async move {
        while let Ok(head) = state_cloned.subscribe_traffics().recv().await {
            let _ = message_tx_cloned.send(Message::TrafficHead(head));
        }
    });

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let ret = App::new(state, addr, message_tx).run(&mut terminal, message_rx);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen,)?;
    terminal.show_cursor()?;

    ret
}

#[derive(Debug)]
struct App {
    state: Arc<State>,
    addr: String,
    message_tx: mpsc::UnboundedSender<Message>,
    traffic_table_state: TableState,
    traffic_heads: Vec<TrafficHead>,
    current_traffic: Option<Box<TrafficDetails>>,
    current_view: View,
    current_tab_index: usize,
    current_tab_content_scroll_offset: u16,
    current_tab_content_scroll_size: Option<u16>,
    should_quit: bool,
}

impl App {
    fn new(state: Arc<State>, addr: &str, message_tx: mpsc::UnboundedSender<Message>) -> Self {
        App {
            state,
            addr: addr.to_string(),
            message_tx,
            traffic_table_state: TableState::default(),
            traffic_heads: Vec::new(),
            current_traffic: None,
            current_view: View::Main,
            current_tab_index: 0,
            current_tab_content_scroll_offset: 0,
            current_tab_content_scroll_size: None,
            should_quit: false,
        }
    }

    fn run(
        mut self,
        terminal: &mut Terminal<impl Backend>,
        mut rx: mpsc::UnboundedReceiver<Message>,
    ) -> Result<()> {
        let tick_rate = Duration::from_millis(TICK_INTERVAL);
        let mut last_tick = Instant::now();
        loop {
            terminal.draw(|frame| self.draw(frame))?;

            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));

            if let Ok(message) = rx.try_recv() {
                self.handle_message(message);
            }

            self.handle_events(timeout)?;

            if last_tick.elapsed() >= tick_rate {
                last_tick = Instant::now();
            }

            if self.should_quit {
                break;
            }
        }
        Ok(())
    }

    fn selected_traffic(&self) -> Option<&TrafficHead> {
        self.traffic_table_state
            .selected()
            .and_then(|v| self.traffic_heads.get(v))
    }

    fn sync_current_traffic(&mut self) {
        let Some(traffic_id) = self.selected_traffic().map(|v| v.id) else {
            return;
        };
        self.current_traffic = None;
        let state = self.state.clone();
        let message_tx = self.message_tx.clone();
        tokio::spawn(async move {
            let Some(traffic) = state.get_traffic(traffic_id).await else {
                return;
            };
            let (req_body, res_body) = traffic.bodies().await;
            let _ = message_tx.send(Message::TrafficDetails(Box::new((
                traffic, req_body, res_body,
            ))));
        });
    }

    fn handle_message(&mut self, message: Message) {
        match message {
            Message::TrafficHead(head) => {
                if let Some(index) = self.traffic_heads.iter().position(|v| v.id == head.id) {
                    self.traffic_heads[index] = head;
                    if self.traffic_table_state.selected() == Some(index)
                        && self.current_view == View::Details
                    {
                        self.sync_current_traffic();
                    }
                } else {
                    let is_empty = self.traffic_heads.is_empty();
                    self.traffic_heads.push(head);
                    if is_empty {
                        self.traffic_table_state.select(Some(0));
                    }
                }
            }
            Message::TrafficDetails(details) => self.current_traffic = Some(details),
        }
    }

    fn handle_events(&mut self, timeout: Duration) -> Result<()> {
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind != event::KeyEventKind::Press {
                    return Ok(());
                }
                match key.code {
                    KeyCode::Esc | KeyCode::Char('q') => {
                        if self.current_view == View::Details {
                            self.current_traffic = None;
                            self.current_view = View::Main;
                        } else {
                            self.should_quit = true;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if self.current_view == View::Main {
                            let i = match self.traffic_table_state.selected() {
                                Some(i) => {
                                    if i >= self.traffic_heads.len() - 1 {
                                        0
                                    } else {
                                        i + 1
                                    }
                                }
                                None => 0,
                            };
                            self.traffic_table_state.select(Some(i));
                        } else if self.current_view == View::Details {
                            if let Some(size) = self.current_tab_content_scroll_size {
                                if size > 0 {
                                    if self.current_tab_content_scroll_offset >= size {
                                        self.current_tab_content_scroll_offset = size
                                    } else {
                                        self.current_tab_content_scroll_offset += 1;
                                    }
                                }
                            }
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if self.current_view == View::Main {
                            let i = match self.traffic_table_state.selected() {
                                Some(i) => {
                                    if i == 0 {
                                        self.traffic_heads.len() - 1
                                    } else {
                                        i - 1
                                    }
                                }
                                None => 0,
                            };
                            self.traffic_table_state.select(Some(i));
                        } else if self.current_view == View::Details {
                            if let Some(size) = self.current_tab_content_scroll_size {
                                if size > 0 && self.current_tab_content_scroll_offset > 0 {
                                    self.current_tab_content_scroll_offset -= 1;
                                }
                            }
                        }
                    }
                    KeyCode::Enter => {
                        if self.current_view == View::Main
                            && self.traffic_table_state.selected().is_some()
                        {
                            self.current_view = View::Details;
                            self.current_tab_content_scroll_offset = 0;
                            self.current_tab_content_scroll_size = None;
                            self.sync_current_traffic();
                        }
                    }
                    KeyCode::Tab | KeyCode::Left | KeyCode::Right => {
                        if self.current_view == View::Details {
                            if self.current_tab_index == 0 {
                                self.current_tab_index = 1;
                            } else {
                                self.current_tab_index = 0;
                            }
                            self.current_tab_content_scroll_offset = 0;
                            self.current_tab_content_scroll_size = None;
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn draw(&mut self, frame: &mut Frame) {
        let chunks =
            Layout::vertical([Constraint::Min(5), Constraint::Length(1)]).split(frame.area());
        match self.current_view {
            View::Main => self.render_main_view(frame, chunks[0]),
            View::Details => self.render_details_view(frame, chunks[0]),
        }
        self.render_footer(frame, chunks[1]);
    }

    fn render_main_view(&mut self, frame: &mut Frame, area: Rect) {
        let block = Block::bordered().title(format!("Proxyfor ({})", self.addr));
        if area.width > LARGE_WIDTH {
            let method_width = 8;
            let status_width = 4;
            let mime_width = 17;
            let size_width = 8;
            let time_delta_width = 6;
            let uri_width = area.width
                - 4
                - method_width
                - status_width
                - mime_width
                - size_width
                - time_delta_width;

            let rows = self.traffic_heads.iter().map(|head| {
                let uri = ellipsis_tail(&head.uri, uri_width - 1);
                let method = ellipsis_tail(&head.method, method_width - 1);
                let status = head.status.map(|v| v.to_string()).unwrap_or_default();
                let mime = ellipsis_head(&head.mime.clone(), mime_width - 1);
                let size = format_size(head.size.map(|v| v as _));
                let time_delta = format_time_delta(head.time.map(|v| v as _));
                [
                    Cell::from(method),
                    Cell::from(uri),
                    Cell::from(status),
                    Cell::from(mime),
                    Cell::from(Text::from(size).alignment(Alignment::Right)),
                    Cell::from(Text::from(time_delta).alignment(Alignment::Right)),
                ]
                .into_iter()
                .collect::<Row>()
                .height(1)
            });
            let table = Table::new(
                rows,
                [
                    Constraint::Length(method_width),
                    Constraint::Min(48),
                    Constraint::Length(status_width),
                    Constraint::Length(mime_width),
                    Constraint::Length(size_width),
                    Constraint::Length(time_delta_width),
                ],
            )
            .highlight_symbol("> ")
            .highlight_style(SELECTED_STYLE)
            .block(block);

            frame.render_stateful_widget(table, area, &mut self.traffic_table_state);
        } else {
            let width = area.width - 4;
            let rows = self.traffic_heads.iter().map(|head| {
                let head_text = generate_title(head, width);
                [Cell::from(head_text)]
                    .into_iter()
                    .collect::<Row>()
                    .height(2)
            });

            let table = Table::new(rows, [Constraint::Percentage(100)])
                .highlight_symbol("> ")
                .highlight_style(SELECTED_STYLE)
                .block(block);

            frame.render_stateful_widget(table, area, &mut self.traffic_table_state);
        }
    }

    fn render_details_view(&mut self, frame: &mut Frame, area: Rect) {
        let is_req = self.current_tab_index == 0;
        let Some(head) = self.selected_traffic() else {
            return;
        };
        let chunks = Layout::vertical([Constraint::Length(2), Constraint::Min(0)]).split(area);
        let title = generate_title(head, area.width);
        frame.render_widget(Text::from(title), chunks[0]);

        let (request_style, response_style) = if is_req {
            (SELECTED_STYLE, Style::default())
        } else {
            (Style::default(), SELECTED_STYLE)
        };
        let Some((traffic, req_body, res_body)) = self.current_traffic.as_deref() else {
            return;
        };
        let tab_second_title = match &traffic.error {
            Some(_) => "Error",
            None => "Response",
        };
        let block = Block::bordered().title(Line::from(vec![
            Span::raw(" "),
            Span::styled("Request", request_style),
            Span::raw(" / "),
            Span::styled(tab_second_title, response_style),
            Span::raw(" "),
        ]));
        let width = area.width - 2;
        let mut texts = vec![];
        let (headers, body, body_file) = if is_req {
            (&traffic.req_headers, req_body, &traffic.req_body_file)
        } else if let Some(error) = &traffic.error {
            texts.push(Line::raw(error));
            (&None, &None, &None)
        } else {
            (&traffic.res_headers, res_body, &traffic.res_body_file)
        };
        if let Some(headers) = headers {
            for header in &headers.items {
                texts.push(Line::raw(format!("{}: {}", header.name, header.value)));
            }
        }
        if let (Some(body), Some(body_file)) = (body, body_file) {
            texts.push(Line::raw("—".repeat(width as _)));
            if body.is_utf8() {
                texts.extend(body.value.lines().map(Line::raw));
            } else {
                texts.push(Line::raw(body_file).style(Style::default().underlined()));
            }
        }
        let paragraph = Paragraph::new(texts)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((self.current_tab_content_scroll_offset, 0));
        if self.current_tab_content_scroll_size.is_none() {
            let line_count = paragraph.line_count(width) as u16;
            let rect_height = chunks[1].height;
            let size = if line_count > rect_height {
                Some(line_count - rect_height)
            } else {
                Some(0)
            };
            self.current_tab_content_scroll_size = size;
        }
        frame.render_widget(paragraph, chunks[1]);
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let text = match self.current_view {
            View::Main => "q: Quit | ↵ Select | ⇅ Navigate".to_string(),
            View::Details => "q: Back | ↹ Switch | ⇅ Scroll".to_string(),
        };
        frame.render_widget(
            Paragraph::new(Text::from(text).style(Style::new().dim())),
            area,
        );
    }
}

fn generate_title(head: &TrafficHead, width: u16) -> String {
    let title = format!("{} {}", head.method, head.uri);
    let description = match head.status {
        Some(status) => {
            let padding = " ".repeat(head.method.len());
            let mime = &head.mime;
            let size = format_size(head.size.map(|v| v as _));
            let time_delta = format_time_delta(head.time.map(|v| v as _));
            format!("{padding} ← {status} {mime} {size} {time_delta}")
        }
        None => "".to_string(),
    };
    let head_text = format!(
        "{}\n{}",
        ellipsis_tail(&title, width),
        ellipsis_tail(&description, width)
    );
    head_text
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum View {
    Main,
    Details,
}

#[derive(Debug)]
enum Message {
    TrafficHead(TrafficHead),
    TrafficDetails(Box<TrafficDetails>),
}

type TrafficDetails = (Traffic, Option<Body>, Option<Body>);

fn ellipsis_tail(text: &str, width: u16) -> String {
    let width = width as _;
    let text_width = text.width();
    if text_width > width {
        format!("{}…", &text[..text_width - 1])
    } else {
        text.to_string()
    }
}

fn ellipsis_head(text: &str, width: u16) -> String {
    let width = width as _;
    let text_width = text.width();
    if text_width > width {
        format!("…{}", &text[text_width - width + 1..])
    } else {
        text.to_string()
    }
}

fn format_size(bytes: Option<u64>) -> String {
    match bytes {
        None => String::new(),
        Some(0) => "0".to_string(),
        Some(bytes) => {
            let prefix = ["b", "kb", "mb", "gb", "tb"];
            let mut i = 0;
            while i < prefix.len() && 1024u64.pow(i as u32 + 1) <= bytes {
                i += 1;
            }
            let precision = if bytes % 1024u64.pow(i as u32) == 0 {
                0
            } else {
                1
            };
            format!(
                "{:.prec$}{}",
                bytes as f64 / 1024f64.powi(i as i32),
                prefix[i],
                prec = precision
            )
        }
    }
}

fn format_time_delta(delta: Option<u64>) -> String {
    let mut delta = match delta {
        Some(ms) => ms,
        None => return String::from(""),
    };

    if delta == 0 {
        return String::from("0");
    }

    if delta > 1000 && delta < 10000 {
        let seconds = delta as f64 / 1000.0;
        return format!("{:.2}s", seconds);
    }

    let prefix = ["ms", "s", "min", "h"];
    let div = [1000, 60, 60];
    let mut i = 0;

    while i < div.len() && delta >= div[i] {
        delta /= div[i];
        i += 1;
    }

    format!("{}{}", delta, prefix[i])
}
