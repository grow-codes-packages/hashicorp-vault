//! Vault-only surface: namespaces (`with_namespace`), capabilities, Vault error refinements
//! (412, 500 on logins and one-shot endpoints, sealed server, enterprise-only routes).

mod support;

use std::time::Duration;

use grow_hashicorp_vault as sdk;
use sdk::core::{ErrorCode, RandomSource};
use sdk::{capability, AppRoleAuth, Capabilities, RetryPolicy, Secret, VaultClient};
use serde_json::json;
use support::*;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A client that retries quickly (to prove that one-shot endpoints are never replayed).
fn retrying(server: &MockServer) -> VaultClient {
    let retry = RetryPolicy {
        max_retries: 3,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
        ..RetryPolicy::default()
    }
    .with_random(RandomSource::fixed(0.5));
    VaultClient::new(builder(server).retry(retry).build().unwrap()).unwrap()
}

#[tokio::test]
async fn with_namespace_sends_the_header_and_keeps_its_own_state() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/app/alpha"))
        .and(header("x-vault-namespace", "team-a/sub"))
        .respond_with(reply("namespace.header_kv"))
        .mount(&server)
        .await;
    on(&server, "GET", "/v1/secret/data/app/alpha", "kv2.read").await;
    on(
        &server,
        "GET",
        "/v1/sys/internal/ui/mounts/secret",
        "kv.detect_v2",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/auth/token/lookup-self",
        "ping.lookup_self",
    )
    .await;
    on(&server, "POST", "/v1/auth/approle/login", "approle.login").await;
    let c = client(&server);
    assert_eq!(c.namespace(), None);
    let team = c.with_namespace("/team-a/sub/").unwrap();
    assert_eq!(team.namespace(), Some("team-a/sub"));
    assert_eq!(team.config().namespace(), Some("team-a/sub"));
    // the view starts with the parent's token
    assert_eq!(team.token().unwrap().expose_secret(), TOKEN);
    team.kv_v2().read("app/alpha", None).await.unwrap();
    let reqs = requests(&server, "/v1/secret/data/app/alpha").await;
    let last = reqs.last().unwrap();
    assert_eq!(last.headers.get("x-vault-namespace").unwrap(), "team-a/sub");
    assert_eq!(last.headers.get("x-vault-token").unwrap(), TOKEN);
    // the parent is unchanged: no namespace header
    c.kv_v2().read("app/alpha", None).await.unwrap();
    let reqs = requests(&server, "/v1/secret/data/app/alpha").await;
    assert!(reqs
        .last()
        .unwrap()
        .headers
        .get("x-vault-namespace")
        .is_none());

    // token changes and logins of the view stay in the view, and the other way round
    team.set_token(Some(Secret::new("view-token-1")));
    assert_eq!(c.token().unwrap().expose_secret(), TOKEN);
    c.set_token(Some(Secret::new("parent-token-2")));
    assert_eq!(team.token().unwrap().expose_secret(), "view-token-1");
    team.auth()
        .login(AppRoleAuth::new("role-1", "secret-id-123456"))
        .await
        .unwrap();
    assert_eq!(team.token().unwrap().expose_secret(), "REDACTED");
    assert_eq!(c.token().unwrap().expose_secret(), "parent-token-2");

    // KV version detection is cached per client
    team.kv().await.unwrap();
    team.kv().await.unwrap();
    c.kv().await.unwrap();
    assert_eq!(
        requests(&server, "/v1/sys/internal/ui/mounts/secret")
            .await
            .len(),
        2
    );

    // "" (and "/") select the root namespace: no header
    let root = team.with_namespace("/").unwrap();
    assert_eq!(root.namespace(), None);
    root.ping().await.unwrap();
    let reqs = requests(&server, "/v1/auth/token/lookup-self").await;
    assert!(reqs
        .last()
        .unwrap()
        .headers
        .get("x-vault-namespace")
        .is_none());
    assert_eq!(c.with_namespace("").unwrap().namespace(), None);

    // whitespace is a CONFIG error
    assert_eq!(
        c.with_namespace("team a").unwrap_err().code(),
        ErrorCode::Config
    );
    assert_eq!(
        c.with_namespace(" /team-b/ ").unwrap().namespace(),
        Some("team-b")
    );
}

#[tokio::test]
async fn with_namespace_close_semantics() {
    let server = MockServer::start().await;
    on(
        &server,
        "GET",
        "/v1/auth/token/lookup-self",
        "ping.lookup_self",
    )
    .await;
    let c = client(&server);
    let a = c.with_namespace("a").unwrap();
    let b = c.with_namespace("b").unwrap();
    // closing a view leaves the parent (and the shared connections) alone
    a.close().await;
    a.close().await;
    assert!(a.is_closed());
    assert_eq!(a.ping().await.unwrap_err().code(), ErrorCode::Cancelled);
    assert!(!c.is_closed());
    c.ping().await.unwrap();
    b.ping().await.unwrap();
    // a dropped view does not keep the parent busy
    drop(c.with_namespace("dropped").unwrap());
    // closing the parent closes every view
    c.close().await;
    assert!(c.is_closed() && b.is_closed());
    assert_eq!(b.ping().await.unwrap_err().code(), ErrorCode::Cancelled);
    // a closed client makes no new views (VALIDATION, as in every language)
    assert_eq!(
        c.with_namespace("late").unwrap_err().code(),
        ErrorCode::Validation
    );
}

#[tokio::test]
async fn capabilities_self_and_for_a_token() {
    let server = MockServer::start().await;
    once(
        &server,
        "POST",
        "/v1/sys/capabilities-self",
        "capabilities_self.plural",
    )
    .await;
    once(
        &server,
        "POST",
        "/v1/sys/capabilities-self",
        "capabilities_self.single",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/sys/capabilities-self",
        "capabilities_self.root",
    )
    .await;
    once(
        &server,
        "POST",
        "/v1/sys/capabilities",
        "capabilities.token",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/sys/capabilities",
        "capabilities.forbidden",
    )
    .await;
    let c = client(&server);
    let sys = c.sys();
    let caps = sys
        .capabilities_self(["/secret/data/app/RUN/x", "secret/data/denied/RUN", " "])
        .await
        .unwrap();
    // surrounding slashes and blank paths are dropped
    assert_eq!(
        sent(&server, "/v1/sys/capabilities-self").await[0],
        json!({"paths": ["secret/data/app/RUN/x", "secret/data/denied/RUN"]})
    );
    assert_eq!(caps.len(), 2);
    assert!(caps.allows("secret/data/app/RUN/x", capability::READ));
    assert!(caps.allows("/secret/data/app/RUN/x/", capability::PATCH));
    assert!(!caps.allows("secret/data/app/RUN/x", capability::LIST));
    assert!(!caps.allows("secret/data/denied/RUN", capability::READ));
    assert_eq!(caps.of("secret/data/denied/RUN"), ["deny"]);
    assert!(!caps.allows("not/requested", capability::READ));
    assert!(caps.of("not/requested").is_empty());

    // one path (the `capabilities` echo of a single path is ignored)
    let one = sys
        .capabilities_self(["transit/encrypt/sdk-aes"])
        .await
        .unwrap();
    assert_eq!(one.len(), 1);
    assert!(one.allows("transit/encrypt/sdk-aes", capability::UPDATE));
    assert!(!one.allows("transit/encrypt/sdk-aes", capability::DELETE));

    // the root token
    let root = sys
        .capabilities_self(vec!["sys/mounts".to_owned()])
        .await
        .unwrap();
    assert!(root.allows("sys/mounts", capability::SUDO));
    assert!(root.allows("sys/mounts", capability::DELETE));

    // another token's capabilities (the token is sent but never logged)
    let other = sys
        .capabilities(
            "hvs.other-token-99",
            &["secret/data/app/RUN/x", "sys/mounts"],
        )
        .await
        .unwrap();
    assert!(other.allows("secret/data/app/RUN/x", capability::CREATE));
    assert!(!other.allows("sys/mounts", capability::READ));
    assert_eq!(
        sent(&server, "/v1/sys/capabilities").await[0],
        json!({"paths": ["secret/data/app/RUN/x", "sys/mounts"], "token": "hvs.other-token-99"})
    );
    // without permission on sys/capabilities: PERMISSION_DENIED, the token redacted
    let err = sys
        .capabilities("hvs.other-token-99", ["sys/mounts"])
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    assert!(!format!("{err:?}").contains("hvs.other-token-99"));

    // argument checks need no request
    let before = server.received_requests().await.unwrap().len();
    let none: [&str; 0] = [];
    for e in [
        sys.capabilities_self(none).await.unwrap_err(),
        sys.capabilities_self(["/", ""]).await.unwrap_err(),
        sys.capabilities("", ["sys/mounts"]).await.unwrap_err(),
        sys.capabilities("t", none).await.unwrap_err(),
    ] {
        assert_eq!(e.code(), ErrorCode::Validation);
    }
    assert_eq!(server.received_requests().await.unwrap().len(), before);

    // the map type itself
    let mut m = Capabilities::default();
    m.0.insert("a".into(), vec!["read".into(), "deny".into()]);
    assert!(!m.allows("a", "read"));
}

#[tokio::test]
async fn vault_error_refinements() {
    let server = MockServer::start().await;
    // 412: Enterprise eventual consistency → UNAVAILABLE, retryable
    on_reply(
        &server,
        "GET",
        "/v1/secret/data/app/lagging",
        json(412, json!({"errors": ["required index state not present"]})),
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/secret/data/app/sealed",
        "sealed.request",
    )
    .await;
    on(&server, "GET", "/v1/sys/namespaces", "namespace.list").await;
    on(&server, "PUT", "/v1/kv1/bad", "error.bad_json").await;
    let c = client(&server);
    let kv = c.kv_v2();
    let err = kv.read("app/lagging", None).await.unwrap_err();
    assert_eq!(
        (err.code(), err.http_status(), err.is_retryable()),
        (ErrorCode::Unavailable, Some(412), true)
    );
    let err = kv.read("app/sealed", None).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    assert!(err.message().contains("Vault is sealed"));
    // namespaces are an Enterprise feature: OSS answers 404
    let err = c
        .transport()
        .get("/v1/sys/namespaces")
        .query("list", "true")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
    // Vault answers malformed JSON with 500
    let err = c
        .transport()
        .put("/v1/kv1/bad")
        .body("{junk", "application/json")
        .idempotent(false)
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
}

#[tokio::test]
async fn one_shot_endpoints_are_never_retried() {
    let server = MockServer::start().await;
    on(
        &server,
        "POST",
        "/v1/auth/kubernetes/login",
        "kubernetes.login_unreachable",
    )
    .await;
    on_reply(
        &server,
        "GET",
        "/v1/database/creds/ro",
        ResponseTemplate::new(500).set_body_json(json!({"errors": ["plugin failed"]})),
    )
    .await;
    on_reply(
        &server,
        "GET",
        "/v1/secret/data/app/flaky",
        ResponseTemplate::new(500).set_body_json(json!({"errors": ["internal error"]})),
    )
    .await;
    let c = retrying(&server);
    // login answered with 500 (plugin cannot reach Kubernetes): UNAVAILABLE, one attempt
    let dir = std::env::temp_dir().join(format!("grow-vault-k8s-once-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let jwt = dir.join("token");
    std::fs::write(&jwt, "k8s.sa.jwt").unwrap();
    let err = c
        .auth()
        .login(sdk::KubernetesAuth::new("sdk-k8s", &jwt))
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    assert_eq!(
        requests(&server, "/v1/auth/kubernetes/login").await.len(),
        1
    );
    std::fs::remove_dir_all(&dir).unwrap();
    // database credentials create a user per call: one attempt
    let err = c.database().get_credentials("ro").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    assert_eq!(requests(&server, "/v1/database/creds/ro").await.len(), 1);
    // an ordinary read is retried
    let _ = c.kv_v2().read("app/flaky", None).await.unwrap_err();
    assert_eq!(
        requests(&server, "/v1/secret/data/app/flaky").await.len(),
        4
    );
}
