mod common;

use crate::common::{
    build_ca, build_client, build_proxy_client, run_proxy_server, start_http_server, start_proxy,
    HELLO_WORLD,
};

use anyhow::Result;
use async_http_proxy::http_connect_tokio;
use futures_util::{SinkExt, StreamExt};
use proxyfor::server::{PrintMode, ServerBuilder};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn test_http() -> Result<()> {
    let (proxy_addr, stop_proxy) = start_proxy(false).await?;
    let (server_addr, stop_server) = start_http_server().await?;

    let proxy_client = build_proxy_client(&proxy_addr.to_string())?;

    let res = proxy_client
        .get(format!("http://localhost:{}/hello", server_addr.port()))
        .send()
        .await?;

    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await?, HELLO_WORLD);

    let _ = stop_server.send(());
    let _ = stop_proxy.send(());
    Ok(())
}

#[tokio::test]
async fn test_websocket() -> Result<()> {
    let (proxy_addr, stop_proxy) = start_proxy(false).await?;
    let (server_addr, stop_server) = start_http_server().await?;

    let mut stream = TcpStream::connect(proxy_addr).await?;
    http_connect_tokio(
        &mut stream,
        &server_addr.ip().to_string(),
        server_addr.port(),
    )
    .await?;

    let (mut ws, res) =
        tokio_tungstenite::client_async(format!("ws://{}", server_addr), stream).await?;

    assert_eq!(res.status(), 101);

    ws.send(Message::Text("hello".to_owned())).await?;

    let message = ws
        .next()
        .await
        .and_then(|v| v.ok())
        .map(|v| v.to_string())
        .unwrap_or_default();
    assert_eq!(message, common::WORLD);

    let _ = stop_server.send(());
    let _ = stop_proxy.send(());
    Ok(())
}

#[tokio::test]
async fn test_reverse_http() -> Result<()> {
    let (server_addr, stop_server) = start_http_server().await?;

    let ca = build_ca()?;
    let server = ServerBuilder::new(ca)
        .print_mode(PrintMode::Nothing)
        .reverse_proxy_url(Some(format!("http://localhost:{}", server_addr.port())))
        .build();

    let (proxy_addr, stop_proxy) = run_proxy_server(server).await?;

    let client = build_client()?;

    let res = client
        .get(format!("http://localhost:{}/hello", proxy_addr.port()))
        .send()
        .await?;

    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await?, HELLO_WORLD);

    let _ = stop_server.send(());
    let _ = stop_proxy.send(());
    Ok(())
}

#[tokio::test]
async fn test_reverse_websocket() -> Result<()> {
    let (server_addr, stop_server) = start_http_server().await?;

    let ca = build_ca()?;
    let server = ServerBuilder::new(ca)
        .print_mode(PrintMode::Nothing)
        .reverse_proxy_url(Some(format!("http://localhost:{}", server_addr.port())))
        .build();

    let (proxy_addr, stop_proxy) = run_proxy_server(server).await?;

    let (mut ws, res) =
        tokio_tungstenite::connect_async(format!("ws://localhost:{}", proxy_addr.port())).await?;

    assert_eq!(res.status(), 101);
    ws.send(Message::Text("hello".to_owned())).await?;

    let message = ws
        .next()
        .await
        .and_then(|v| v.ok())
        .map(|v| v.to_string())
        .unwrap_or_default();
    assert_eq!(message, common::WORLD);

    let _ = stop_server.send(());
    let _ = stop_proxy.send(());
    Ok(())
}
