mod common;

use crate::common::{
    build_client, build_proxy_client, fetch_subscribe, mask_text, start_http_server, start_proxy,
    HELLO_WORLD,
};

use anyhow::Result;
use async_http_proxy::http_connect_tokio;
use futures_util::SinkExt;
use proxyfor::server::WEB_PREFIX;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn test_web_index() -> Result<()> {
    let (proxy_addr, stop_proxy) = start_proxy(true).await?;

    let client = build_client()?;

    let res = client
        .get(format!(
            "http://localhost:{}{}",
            proxy_addr.port(),
            WEB_PREFIX
        ))
        .send()
        .await?;

    let status = res.status();
    let text = res.text().await?;
    assert_eq!(status, 200);
    assert!(text.contains("<title>proxyfor</title>"));

    let _ = stop_proxy.send(());
    Ok(())
}

#[tokio::test]
async fn test_list_traffics() -> Result<()> {
    let (proxy_addr, stop_proxy) = start_proxy(true).await?;
    let (server_addr, stop_server) = start_http_server().await?;

    let proxy_client = build_proxy_client(&proxy_addr.to_string())?;

    let res = proxy_client
        .get(format!("http://localhost:{}/hello", server_addr.port()))
        .send()
        .await?;

    assert_eq!(res.status(), 200);

    let res = proxy_client
        .get(format!(
            "http://localhost:{}/hello/gzip",
            server_addr.port()
        ))
        .send()
        .await?;

    assert_eq!(res.status(), 200);

    let res = proxy_client
        .post(format!("http://localhost:{}/echo", server_addr.port()))
        .header("content-type", "text/plain")
        .body(HELLO_WORLD)
        .send()
        .await?;

    assert_eq!(res.status(), 200);

    let mut output = vec![];

    let client = build_client()?;
    let res = client
        .get(format!(
            "http://localhost:{}{}/traffics",
            proxy_addr.port(),
            WEB_PREFIX
        ))
        .send()
        .await?;

    assert_eq!(res.status(), 200);

    output.push("/traffics".into());
    output.push(res.text().await?);

    let client = build_client()?;
    let res = client
        .get(format!(
            "http://localhost:{}{}/traffics?markdown",
            proxy_addr.port(),
            WEB_PREFIX
        ))
        .send()
        .await?;

    assert_eq!(res.status(), 200);

    output.push("/traffics?markdown".into());
    output.push(res.text().await?);

    let client = build_client()?;
    let res = client
        .get(format!(
            "http://localhost:{}{}/traffics?har",
            proxy_addr.port(),
            WEB_PREFIX
        ))
        .send()
        .await?;

    assert_eq!(res.status(), 200);

    output.push("/traffics?har".into());
    output.push(res.text().await?);

    let client = build_client()?;
    let res = client
        .get(format!(
            "http://localhost:{}{}/traffics?curl",
            proxy_addr.port(),
            WEB_PREFIX
        ))
        .send()
        .await?;

    assert_eq!(res.status(), 200);

    output.push("/traffics?curl".into());
    output.push(res.text().await?);

    let output = output.join("\n\n");
    let output = mask_text(&output);

    insta::assert_snapshot!(output);

    let _ = stop_server.send(());
    let _ = stop_proxy.send(());
    Ok(())
}

#[tokio::test]
async fn test_get_traffic() -> Result<()> {
    let (proxy_addr, stop_proxy) = start_proxy(true).await?;
    let (server_addr, stop_server) = start_http_server().await?;

    let proxy_client = build_proxy_client(&proxy_addr.to_string())?;

    let res = proxy_client
        .post(format!("http://localhost:{}/echo", server_addr.port()))
        .header("content-type", "text/plain")
        .body(HELLO_WORLD)
        .send()
        .await?;

    assert_eq!(res.status(), 200);

    let mut output = vec![];

    let id = 1;
    let client = build_client()?;
    let res = client
        .get(format!(
            "http://localhost:{}{}/traffic/{}",
            proxy_addr.port(),
            WEB_PREFIX,
            id
        ))
        .send()
        .await?;

    assert_eq!(res.status(), 200);

    output.push("/traffic/:id".into());
    output.push(res.text().await?);

    let client = build_client()?;
    let res = client
        .get(format!(
            "http://localhost:{}{}/traffic/{}?markdown",
            proxy_addr.port(),
            WEB_PREFIX,
            id
        ))
        .send()
        .await?;

    assert_eq!(res.status(), 200);

    output.push("/traffic/:id?markdown".into());
    output.push(res.text().await?);

    let client = build_client()?;
    let res = client
        .get(format!(
            "http://localhost:{}{}/traffic/{}?har",
            proxy_addr.port(),
            WEB_PREFIX,
            id
        ))
        .send()
        .await?;

    assert_eq!(res.status(), 200);

    output.push("/traffic/:id?har".into());
    output.push(res.text().await?);

    let client = build_client()?;
    let res = client
        .get(format!(
            "http://localhost:{}{}/traffic/{}?curl",
            proxy_addr.port(),
            WEB_PREFIX,
            id
        ))
        .send()
        .await?;

    assert_eq!(res.status(), 200);

    output.push("/traffic/:id?curl".into());
    output.push(res.text().await?);

    let output = output.join("\n\n");
    let output = mask_text(&output);

    insta::assert_snapshot!(output);

    let _ = stop_server.send(());
    let _ = stop_proxy.send(());
    Ok(())
}

#[tokio::test]
async fn test_subscribe_traffics() -> Result<()> {
    let (proxy_addr, stop_proxy) = start_proxy(true).await?;
    let (server_addr, stop_server) = start_http_server().await?;

    let proxy_client = build_proxy_client(&proxy_addr.to_string())?;

    for _ in 0..2 {
        let res = proxy_client
            .post(format!("http://localhost:{}/echo", server_addr.port()))
            .header("content-type", "text/plain")
            .body(HELLO_WORLD)
            .send()
            .await?;

        assert_eq!(res.status(), 200);
    }

    let output = fetch_subscribe(
        &format!(
            "http://localhost:{}{}/subscribe/traffics",
            proxy_addr.port(),
            WEB_PREFIX,
        ),
        2,
    )
    .await?;

    let output = mask_text(&output);
    insta::assert_snapshot!(output);

    let _ = stop_server.send(());
    let _ = stop_proxy.send(());
    Ok(())
}

#[tokio::test]
async fn test_subscribe_websocket() -> Result<()> {
    let (proxy_addr, stop_proxy) = start_proxy(true).await?;
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

    ws.send(Message::Text("hello".to_string())).await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    ws.send(Message::Text("hello".to_string())).await?;

    let output = fetch_subscribe(
        &format!(
            "http://localhost:{}{}/subscribe/websocket/1",
            proxy_addr.port(),
            WEB_PREFIX,
        ),
        4,
    )
    .await?;

    let output = mask_text(&output);
    insta::assert_snapshot!(output);

    let _ = stop_server.send(());
    let _ = stop_proxy.send(());

    Ok(())
}
