use crate::{
    state::State,
    traffic::{Body, Traffic, TrafficHead},
    utils::*,
};

use anyhow::Result;
use crossterm::{
    event::{self, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    prelude::*,
    style::palette::material::GRAY,
    text::{Line, Span},
    widgets::{Block, Cell, Clear, Paragraph, Row, Table, TableState, Wrap},
};
use std::{
    io,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tui_input::{backend::crossterm::EventHandler, Input};

const TICK_INTERVAL: u64 = 250;
const MESSAGE_TIMEOUT: u64 = 5000;
const LARGE_WIDTH: u16 = 100;
const SELECTED_STYLE: Style = Style::new().bg(GRAY.c800).add_modifier(Modifier::BOLD);
const EXPORT_ALL_TRAFFICS: &str = "proxyfor_all_traffics";

const COPY_ACTIONS: [(&str, &str); 5] = [
    ("Copy as Markdown", "markdown"),
    ("Copy as cURL", "curl"),
    ("Copy as HAR", "har"),
    ("Copy Request Body", "req-body"),
    ("Copy Response Body", "res-body"),
];

const EXPORT_ACTIONS: [(&str, &str); 3] = [
    ("Export all as Markdown", "markdown"),
    ("Export all as cURL", "curl"),
    ("Export all as HAR", "har"),
];

pub async fn run(state: Arc<State>, addr: &str) -> Result<()> {
    let mut traffic_rx = state.subscribe_traffics();
    let (message_tx, message_rx) = mpsc::unbounded_channel();
    let message_tx_cloned = message_tx.clone();
    tokio::spawn(async move {
        while let Ok(head) = traffic_rx.recv().await {
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
    current_popup: Option<Popup>,
    current_notifier: Option<Notifier>,
    input_mode: bool,
    search_input: Input,
    should_quit: bool,
    step: u64,
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
            current_popup: None,
            current_notifier: None,
            input_mode: false,
            search_input: Input::default(),
            should_quit: false,
            step: 0,
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

            if self.should_quit {
                break;
            }

            if last_tick.elapsed() >= tick_rate {
                last_tick = Instant::now();
            }

            self.maybe_clear_notifier();

            self.step += 1;
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
        let state = self.state.clone();
        let message_tx = self.message_tx.clone();
        tokio::spawn(async move {
            let Some(traffic) = state.get_traffic(traffic_id).await else {
                return;
            };
            let (req_body, res_body) = traffic.bodies(false).await;
            let _ = message_tx.send(Message::TrafficDetails(Box::new((
                traffic, req_body, res_body,
            ))));
        });
        self.current_traffic = None;
    }

    fn run_copy_command(&mut self, idx: usize) {
        let Some(traffic_id) = self.selected_traffic().map(|v| v.id) else {
            return;
        };
        let Some((_, format)) = COPY_ACTIONS.get(idx) else {
            return;
        };
        let state = self.state.clone();
        let message_tx = self.message_tx.clone();
        tokio::spawn(async move {
            match state.export_traffic(traffic_id, format).await {
                Ok((data, _)) => {
                    let message = match set_text(&data) {
                        Ok(_) => Message::Info("Copied".into()),
                        Err(err) => Message::Error(err.to_string()),
                    };
                    let _ = message_tx.send(message);
                }
                Err(err) => {
                    let _ = message_tx.send(Message::Error(err.to_string()));
                }
            };
        });
    }

    fn run_export_command(&mut self, idx: usize) {
        let Some((_, format)) = EXPORT_ACTIONS.get(idx) else {
            return;
        };
        let state = self.state.clone();
        let message_tx = self.message_tx.clone();
        tokio::spawn(async move {
            match state.export_all_traffics(format).await {
                Ok((data, _)) => {
                    let ext = match *format {
                        "markdown" => ".md",
                        "curl" => ".sh",
                        "har" => ".har",
                        _ => ".txt",
                    };
                    let path = format!("{EXPORT_ALL_TRAFFICS}{ext}");
                    let message = match tokio::fs::write(&path, data).await {
                        Ok(_) => Message::Info(format!("Exported to {path}")),
                        Err(err) => Message::Error(err.to_string()),
                    };
                    let _ = message_tx.send(message);
                }
                Err(err) => {
                    let _ = message_tx.send(Message::Error(err.to_string()));
                }
            };
        });
    }

    fn notify(&mut self, message: &str, is_error: bool) {
        let step = MESSAGE_TIMEOUT / TICK_INTERVAL;
        self.current_notifier = Some((message.to_string(), is_error, self.step + step));
    }

    fn maybe_clear_notifier(&mut self) {
        if let Some((_, _, timeout_step)) = &self.current_notifier {
            if self.step > *timeout_step {
                self.current_notifier = None;
            }
        }
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
            Message::Error(error) => self.notify(&error, true),
            Message::Info(info) => self.notify(&info, false),
        }
    }

    fn handle_events(&mut self, timeout: Duration) -> Result<()> {
        if crossterm::event::poll(timeout)? {
            let event = event::read()?;
            if let event::Event::Key(key) = event {
                if key.kind != event::KeyEventKind::Press {
                    return Ok(());
                }
                if self.input_mode {
                    match key.code {
                        KeyCode::Esc => {
                            self.input_mode = false;
                            self.search_input.reset();
                        }
                        KeyCode::Enter => {
                            self.input_mode = false;
                        }
                        _ => {
                            self.search_input.handle_event(&event);
                        }
                    }
                    return Ok(());
                }
                match key.code {
                    KeyCode::Esc | KeyCode::Char('q') => {
                        if self.current_popup.is_some() {
                            self.current_popup = None;
                        } else if self.current_view == View::Details {
                            self.current_traffic = None;
                            self.current_view = View::Main;
                        } else {
                            self.should_quit = true;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if let Some(popup) = self.current_popup.as_mut() {
                            match popup {
                                Popup::Copy(idx) => {
                                    *idx = next_idx(COPY_ACTIONS.len(), *idx);
                                }
                                Popup::Export(idx) => {
                                    *idx = next_idx(EXPORT_ACTIONS.len(), *idx);
                                }
                            }
                        } else if self.current_view == View::Main {
                            let i = match self.traffic_table_state.selected() {
                                Some(i) => next_idx(self.traffic_heads.len(), i),
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
                        if let Some(popup) = self.current_popup.as_mut() {
                            match popup {
                                Popup::Copy(idx) => {
                                    *idx = prev_idx(COPY_ACTIONS.len(), *idx);
                                }
                                Popup::Export(idx) => {
                                    *idx = prev_idx(EXPORT_ACTIONS.len(), *idx);
                                }
                            }
                        } else if self.current_view == View::Main {
                            let i = match self.traffic_table_state.selected() {
                                Some(i) => prev_idx(self.traffic_heads.len(), i),
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
                        if let Some(popup) = &self.current_popup {
                            match popup {
                                Popup::Copy(idx) => self.run_copy_command(*idx),
                                Popup::Export(idx) => self.run_export_command(*idx),
                            }
                            self.current_popup = None;
                        } else if self.current_view == View::Main
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
                    KeyCode::Char('c') => {
                        if self.current_popup.is_none() {
                            if self.selected_traffic().is_none() {
                                self.notify("No traffic selected", true);
                            } else {
                                self.current_popup = Some(Popup::Copy(0));
                            }
                        }
                    }
                    KeyCode::Char('e') => {
                        if self.current_popup.is_none() {
                            if self.traffic_heads.is_empty() {
                                self.notify("No traffics", true);
                            } else {
                                self.current_popup = Some(Popup::Export(0));
                            }
                        }
                    }
                    KeyCode::Char('/') => {
                        if self.current_view == View::Main {
                            self.input_mode = true;
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
        self.render_popup(frame);
        self.render_input(frame);
    }

    fn render_main_view(&mut self, frame: &mut Frame, area: Rect) {
        let block = Block::bordered().title(format!("Proxyfor ({})", self.addr));
        if area.width > LARGE_WIDTH {
            let method_width = 4;
            let status_width = 3;
            let mime_width = 16;
            let size_width = 7;
            let time_delta_width = 5;
            let uri_width = area.width
                - 9 // 2(borders)+2(highlight-symbol)+5(columns-gap)
                - method_width
                - status_width
                - mime_width
                - size_width
                - time_delta_width;

            let words = self
                .search_input
                .value()
                .split_whitespace()
                .collect::<Vec<_>>();
            let rows = self.traffic_heads.iter().filter_map(|head| {
                if words.iter().any(|word| !head.test_filter(word)) {
                    return None;
                }
                let uri = ellipsis_tail(&head.uri, uri_width);
                let method = ellipsis_tail(&head.method, method_width);
                let status = head.status.map(|v| v.to_string()).unwrap_or_default();
                let mime = ellipsis_head(&head.mime.clone(), mime_width);
                let size = format_size(head.size.map(|v| v as _));
                let time_delta = format_time_delta(head.time.map(|v| v as _));
                let widget = [
                    Cell::from(method),
                    Cell::from(uri),
                    Cell::from(status),
                    Cell::from(mime),
                    Cell::from(Text::from(size).alignment(Alignment::Right)),
                    Cell::from(Text::from(time_delta).alignment(Alignment::Right)),
                ]
                .into_iter()
                .collect::<Row>()
                .height(1);
                Some(widget)
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
        let (headers, body) = if is_req {
            (&traffic.req_headers, req_body)
        } else if let Some(error) = &traffic.error {
            texts.push(Line::raw(error));
            (&None, &None)
        } else {
            (&traffic.res_headers, res_body)
        };
        if let Some(headers) = headers {
            for header in &headers.items {
                texts.push(Line::raw(format!("{}: {}", header.name, header.value)));
            }
        }
        if let Some(body) = body {
            texts.push(Line::raw("—".repeat(width as _)));
            if body.is_utf8() {
                texts.extend(body.value.lines().map(Line::raw));
            } else {
                texts.push(Line::raw(&body.value).style(Style::default().underlined()));
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
        match &self.current_notifier {
            Some(notifier) => self.render_notifier(frame, area, notifier),
            None => self.render_help_banner(frame, area),
        }
    }

    fn render_notifier(&self, frame: &mut Frame, area: Rect, (message, is_error, _): &Notifier) {
        let (message, style) = if *is_error {
            (format!("Error: {message}"), Style::new().fg(Color::Red))
        } else {
            (format!("✓ {message}"), Style::new().fg(Color::Green))
        };
        let text = Text::from(message).style(style);
        frame.render_widget(Paragraph::new(text), area);
    }

    fn render_help_banner(&self, frame: &mut Frame, area: Rect) {
        let text = match self.current_view {
            View::Main => {
                "↵ Select | ⇅ Navigate | / Search | c: Copy | e: Export | q: Quit".to_string()
            }
            View::Details => "↹ Switch | ⇅ Scroll | c: Copy | e: Export | q: Back".to_string(),
        };
        frame.render_widget(
            Paragraph::new(Text::from(text).style(Style::new().dim())),
            area,
        );
    }

    fn render_popup(&self, frame: &mut Frame) {
        match &self.current_popup {
            Some(Popup::Copy(idx)) => self.render_action_popup(frame, *idx, &COPY_ACTIONS, 24),
            Some(Popup::Export(idx)) => self.render_action_popup(frame, *idx, &EXPORT_ACTIONS, 30),
            None => {}
        }
    }

    fn render_action_popup(
        &self,
        frame: &mut Frame,
        idx: usize,
        actions: &[(&str, &str)],
        width: u16,
    ) {
        let block = Block::bordered().title("Actions");
        let texts = actions
            .iter()
            .enumerate()
            .map(|(i, (v, _))| {
                let style = if i == idx {
                    SELECTED_STYLE
                } else {
                    Style::default()
                };
                Line::raw(v.to_string()).style(style)
            })
            .collect::<Vec<Line>>();
        let paragraph = Paragraph::new(texts).block(block);
        let area = popup_absolute_area(frame.area(), width, actions.len() as u16 + 2);
        frame.render_widget(Clear, area);
        frame.render_widget(paragraph, area);
    }

    fn render_input(&self, frame: &mut Frame) {
        if !self.input_mode && self.search_input.value().is_empty() {
            return;
        }
        let space = if self.input_mode { " " } else { "" };
        let line = Line::raw(format!("|search: {}{}|", self.search_input.value(), space));
        let frame_area = frame.area();
        let y = frame_area.height - 2;
        let w: u16 = line.width() as _;
        let area = Rect {
            x: 1,
            y,
            width: w,
            height: 1,
        };
        frame.render_widget(Clear, area);
        frame.render_widget(line, area);
        frame.set_cursor_position((w.saturating_sub(1), y));
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

fn popup_absolute_area(area: Rect, width: u16, height: u16) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(area.height.saturating_sub(height) / 2),
                Constraint::Length(height),
                Constraint::Min(0),
            ]
            .as_ref(),
        )
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Length(area.width.saturating_sub(width) / 2),
                Constraint::Length(width),
                Constraint::Min(0),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}

#[derive(Debug, Clone, PartialEq)]
enum View {
    Main,
    Details,
}

#[derive(Debug)]
enum Message {
    TrafficHead(TrafficHead),
    TrafficDetails(Box<TrafficDetails>),
    Info(String),
    Error(String),
}

type TrafficDetails = (Traffic, Option<Body>, Option<Body>);

type Notifier = (String, bool, u64); // (message, is_error, timeout_step)

#[derive(Debug, Clone, PartialEq)]
enum Popup {
    Copy(usize),
    Export(usize),
}
