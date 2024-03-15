mod common;

use crate::common::{
    build_ca, build_client, build_proxy_client, mask_text, run_proxy_server, start_http_server,
    HELLO_WORLD,
};

use anyhow::Result;
use proxyfor::{
    filter::parse_title_filters,
    server::{PrintMode, ServerBuilder, WEB_PREFIX},
};

#[tokio::test]
async fn test_title_filter() -> Result<()> {
    let (server_addr, stop_server) = start_http_server().await?;

    let ca = build_ca()?;

    let server = ServerBuilder::new(ca)
        .print_mode(PrintMode::Nothing)
        .web(true)
        .title_filters(parse_title_filters(&["hello".into()])?)
        .reverse_proxy_url(Some(format!("http://localhost:{}", server_addr.port())))
        .build();

    let (proxy_addr, stop_proxy) = run_proxy_server(server).await?;

    let proxy_client = build_proxy_client(&proxy_addr.to_string())?;

    let res = proxy_client
        .get(format!("http://localhost:{}/hello", server_addr.port()))
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

    let output = res.text().await?;
    let output = mask_text(&output);
    insta::assert_snapshot!(output);

    let _ = stop_server.send(());
    let _ = stop_proxy.send(());
    Ok(())
}

#[tokio::test]
async fn test_mime_filter() -> Result<()> {
    let (server_addr, stop_server) = start_http_server().await?;

    let ca = build_ca()?;

    let server = ServerBuilder::new(ca)
        .print_mode(PrintMode::Nothing)
        .mime_filters(vec!["application/json".into()])
        .reverse_proxy_url(Some(format!("http://localhost:{}", server_addr.port())))
        .web(true)
        .build();

    let (proxy_addr, stop_proxy) = run_proxy_server(server).await?;

    let proxy_client = build_proxy_client(&proxy_addr.to_string())?;

    let res = proxy_client
        .get(format!("http://localhost:{}/hello", server_addr.port()))
        .send()
        .await?;

    assert_eq!(res.status(), 200);

    let res = proxy_client
        .post(format!("http://localhost:{}/echo", server_addr.port()))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await?;

    assert_eq!(res.status(), 200);

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

    let output = res.text().await?;
    let output = mask_text(&output);
    insta::assert_snapshot!(output);

    let _ = stop_server.send(());
    let _ = stop_proxy.send(());
    Ok(())
}
