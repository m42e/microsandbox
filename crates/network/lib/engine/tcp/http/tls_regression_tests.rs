//! Regression coverage for TLS over the guest-facing HTTP proxy.

use tokio::net::TcpListener;

use crate::secrets::handle::SecretsHandle;
use crate::tcp::connection::ProxyConnectStatus;

use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn client_hello(host: &str) -> Vec<u8> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let mut client = rustls::ClientConnection::new(
        Arc::new(config),
        rustls::pki_types::ServerName::try_from(host.to_owned()).unwrap(),
    )
    .unwrap();
    let mut data = Vec::new();
    client.write_tls(&mut data).unwrap();
    data
}

fn tls_state() -> Arc<TlsState> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    Arc::new(
        TlsState::new(
            microsandbox_types::TlsConfig::default(),
            SecretsHandle::new(SecretsConfig::default()),
        )
        .unwrap(),
    )
}

async fn upstream_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, server) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    (client.unwrap(), server.unwrap().0)
}

async fn ip_connect_policy_result(policy: NetworkPolicy, denied: bool) {
    let shared = Arc::new(SharedState::new(32));
    let address: SocketAddr = "203.0.113.10:443".parse().unwrap();
    let (upstream, _server) = upstream_pair().await;
    let (_input, receiver) = mpsc::channel(32);
    let (sender, mut output) = mpsc::channel(32);
    let status = Arc::new(ProxyConnectState::new());
    let proxy = TlsProxy::new(
        address,
        UpstreamTcpTarget::direct(address),
        receiver,
        sender,
        shared,
        tls_state(),
        Arc::new(policy),
        true,
        status.clone(),
        None,
    )
    .with_upstream(upstream)
    .with_initial_buf(client_hello("blocked.example"))
    .with_proxy_dns_address();
    let task = tokio::spawn(proxy.run());
    if denied {
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.status(), ProxyConnectStatus::PolicyDenied);
        assert!(output.recv().await.is_none());
    } else {
        let bytes = tokio::time::timeout(Duration::from_secs(3), output.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!bytes.is_empty());
        assert_ne!(status.status(), ProxyConnectStatus::PolicyDenied);
        task.abort();
        let _ = task.await;
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn ip_connect_enforces_sni_hostname_denies() {
    for destination in [
        serde_json::json!({"domain": "blocked.example"}),
        serde_json::json!({"domain_suffix": "example"}),
        serde_json::json!({"cidr": "203.0.113.0/24"}),
    ] {
        let policy = serde_json::from_value(serde_json::json!({
            "default_egress": "allow", "default_ingress": "allow", "rules": [{
                "direction": "egress", "destination": destination, "action": "deny"
            }]
        }))
        .unwrap();
        ip_connect_policy_result(policy, true).await;
    }
    ip_connect_policy_result(NetworkPolicy::allow_all(), false).await;
}

#[tokio::test]
async fn ip_connect_retains_strict_hostname_bypass_checks() {
    let shared = Arc::new(SharedState::new(32));
    let address: SocketAddr = "203.0.113.10:443".parse().unwrap();
    shared.cache_resolved_hostname(
        "blocked.example",
        crate::netstack::shared::ResolvedHostnameFamily::Ipv4,
        [address.ip()],
        Duration::from_secs(30),
    );
    let policy = serde_json::from_value(serde_json::json!({
        "default_egress": "deny", "default_ingress": "allow", "rules": [{
            "direction": "egress", "destination": {"domain": "blocked.example"}, "action": "allow"
        }]
    }))
    .unwrap();
    let (upstream, mut server) = upstream_pair().await;
    let (_input, receiver) = mpsc::channel(32);
    let (sender, mut output) = mpsc::channel(32);
    let status = Arc::new(ProxyConnectState::new());
    let _ = tls_state();
    let tls = Arc::new(
        TlsState::new(
            microsandbox_types::TlsConfig {
                bypass: vec!["blocked.example".into()],
                ..Default::default()
            },
            SecretsHandle::new(SecretsConfig::default()),
        )
        .unwrap(),
    );
    let proxy = TlsProxy::new(
        address,
        UpstreamTcpTarget::direct(address),
        receiver,
        sender,
        shared,
        tls,
        Arc::new(policy),
        true,
        status.clone(),
        None,
    )
    .with_upstream(upstream)
    .with_initial_buf(client_hello("blocked.example"))
    .with_proxy_dns_address();
    tokio::time::timeout(Duration::from_secs(3), proxy.run())
        .await
        .unwrap();
    assert_eq!(status.status(), ProxyConnectStatus::PolicyDenied);
    assert!(output.recv().await.is_none());
    let mut bytes = Vec::new();
    server.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.is_empty());
}
