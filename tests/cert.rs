mod common;

use crate::common::{build_proxy_client, start_http_server, start_proxy};
use proxyfor::server::CERT_PREFIX;

use anyhow::Result;

#[tokio::test]
async fn test_cert_page() -> Result<()> {
    let (proxy_addr, stop_proxy) = start_proxy(false).await?;
    let (_server_addr, stop_server) = start_http_server().await?;

    let client = build_proxy_client(&proxy_addr.to_string())?;

    let res = client.get(CERT_PREFIX).send().await?;

    assert_eq!(res.status(), 200);
    insta::assert_snapshot!(res.text().await?);

    let _ = stop_server.send(());
    let _ = stop_proxy.send(());
    Ok(())
}

#[tokio::test]
async fn test_cert_cer() -> Result<()> {
    let (proxy_addr, stop_proxy) = start_proxy(false).await?;
    let (_server_addr, stop_server) = start_http_server().await?;

    let client = build_proxy_client(&proxy_addr.to_string())?;

    let res = client
        .get(format!("{}proxyfor-ca-cert.cer", CERT_PREFIX))
        .send()
        .await?;

    assert_eq!(res.status(), 200);
    insta::assert_snapshot!(res.text().await?);

    let _ = stop_server.send(());
    let _ = stop_proxy.send(());
    Ok(())
}

#[tokio::test]
async fn test_cert_pem() -> Result<()> {
    let (proxy_addr, stop_proxy) = start_proxy(false).await?;
    let (_server_addr, stop_server) = start_http_server().await?;

    let client = build_proxy_client(&proxy_addr.to_string())?;

    let res = client
        .get(format!("{}proxyfor-ca-cert.pem", CERT_PREFIX))
        .send()
        .await?;

    assert_eq!(res.status(), 200);
    insta::assert_snapshot!(res.text().await?);

    let _ = stop_server.send(());
    let _ = stop_proxy.send(());
    Ok(())
}
