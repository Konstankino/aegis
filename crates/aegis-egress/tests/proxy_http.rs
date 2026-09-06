//! Integration test: boot the egress proxy on an ephemeral port and drive it over real HTTP,
//! asserting allow (200), deny (403), and query-param stripping end to end.

use aegis_egress::{app, Allowlist};
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

fn test_allowlist() -> Allowlist {
    let toml = r#"
        hosts = ["api.internal.example"]
        schemes = ["https"]
        [permitted_params]
        "api.internal.example" = ["page"]
    "#;
    Allowlist::from_toml(toml).unwrap()
}

/// Boot the proxy on 127.0.0.1:0 and return its bound address.
async fn spawn_proxy() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = app::router(test_allowlist());
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    addr
}

fn encode(url: &str) -> String {
    url::form_urlencoded::byte_serialize(url.as_bytes()).collect()
}

async fn get(addr: std::net::SocketAddr, target: &str) -> (u16, String) {
    let client: Client<_, axum::body::Body> = Client::builder(TokioExecutor::new()).build_http();
    let uri: hyper::Uri = format!("http://{addr}/decide?url={}", encode(target))
        .parse()
        .unwrap();
    let resp = client.get(uri).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn allowlisted_destination_returns_200_and_strips_params() {
    let addr = spawn_proxy().await;
    let (status, body) = get(addr, "https://api.internal.example/v1?page=2&leak=SECRET").await;
    assert_eq!(status, 200, "body={body}");
    assert!(body.contains("\"decision\":\"allow\""));
    assert!(body.contains("page=2"));
    assert!(!body.contains("leak"));
    assert!(!body.contains("SECRET"));
}

#[tokio::test]
async fn unlisted_destination_returns_403() {
    let addr = spawn_proxy().await;
    let (status, body) = get(addr, "https://evil.example/collect?data=SECRET").await;
    assert_eq!(status, 403, "body={body}");
    assert!(body.contains("\"decision\":\"deny\""));
}

#[tokio::test]
async fn healthz_ok() {
    let addr = spawn_proxy().await;
    let client: Client<_, axum::body::Body> = Client::builder(TokioExecutor::new()).build_http();
    let uri: hyper::Uri = format!("http://{addr}/healthz").parse().unwrap();
    let resp = client.get(uri).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}
