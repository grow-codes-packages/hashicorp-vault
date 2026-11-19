//! System/admin module, response wrapping and the `testing` lifecycle helpers.

mod support;

use std::collections::BTreeMap;
use std::time::Duration;

use grow_hashicorp_vault as sdk;
use sdk::core::ErrorCode;
use sdk::{AppRoleOptions, MountOptions, SecretIdOptions};
use serde_json::json;
use support::*;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer};

#[tokio::test]
async fn seal_status_and_leader() {
    let server = MockServer::start().await;
    on(&server, "GET", "/v1/sys/seal-status", "seal_status").await;
    on(&server, "GET", "/v1/sys/leader", "leader").await;
    let c = client(&server);
    let s = c.sys().seal_status().await.unwrap();
    assert_eq!(s.seal_type, "shamir");
    assert!(s.initialized && !s.sealed && !s.recovery_seal);
    assert_eq!((s.t, s.n, s.progress), (1, 1, 0));
    assert_eq!(s.version, "2.2.2");
    assert_eq!(s.storage_type, "file");
    assert_eq!(s.build_date, "2026-11-11T13:53:02Z");
    assert!(!s.cluster_id.is_empty() && !s.cluster_name.is_empty() && !s.build_date.is_empty());
    let l = c.sys().leader().await.unwrap();
    // file storage: no HA, zero active time, no raft indexes
    assert!(!l.ha_enabled && !l.is_self);
    assert_eq!(l.leader_address, "");
    assert_eq!((l.raft_committed_index, l.raft_applied_index), (0, 0));
    assert!(l.active_time.is_none());
    assert!(l.leader_cluster_address.is_empty());
    assert!(!l.performance_standby);
    assert_eq!(l.performance_standby_last_remote_wal, 0);
    // Enterprise performance standby fields
    let ent = MockServer::start().await;
    on_reply(
        &ent,
        "GET",
        "/v1/sys/leader",
        json(
            200,
            json!({"ha_enabled": true, "is_self": false, "performance_standby": true,
                   "performance_standby_last_remote_wal": 42,
                   "active_time": "2026-11-18T20:25:45Z"}),
        ),
    )
    .await;
    let l = client(&ent).sys().leader().await.unwrap();
    assert!(l.ha_enabled && l.performance_standby && l.active_time.is_some());
    assert_eq!(l.performance_standby_last_remote_wal, 42);
    let r = requests(&server, "/v1/sys/seal-status").await;
    assert!(r[0].headers.get("x-vault-token").is_none());
}

#[tokio::test]
async fn policies() {
    let server = MockServer::start().await;
    on(&server, "PUT", "/v1/sys/policies/acl/p1", "policy.write").await;
    on(
        &server,
        "PUT",
        "/v1/sys/policies/acl/bad",
        "policy.write_invalid",
    )
    .await;
    on(&server, "GET", "/v1/sys/policies/acl/p1", "policy.read").await;
    on(
        &server,
        "GET",
        "/v1/sys/policies/acl/missing",
        "policy.read_missing",
    )
    .await;
    on_list(&server, "/v1/sys/policies/acl", "policy.list").await;
    on(
        &server,
        "DELETE",
        "/v1/sys/policies/acl/p1",
        "policy.delete",
    )
    .await;
    let c = client(&server);
    let sys = c.sys();
    let hcl = "path \"secret/*\" { capabilities = [\"read\"] }";
    sys.write_policy("p1", hcl).await.unwrap();
    assert_eq!(
        sent(&server, "/v1/sys/policies/acl/p1").await[0],
        json!({"policy": hcl})
    );
    assert_eq!(
        sys.write_policy("bad", "nope {").await.unwrap_err().code(),
        ErrorCode::Validation
    );
    let p = sys.read_policy("p1").await.unwrap();
    assert_eq!(p.name, "rt-pol-RUN");
    assert!(p.policy.contains("capabilities"));
    assert_eq!(
        sys.read_policy("missing").await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    let names = sys.list_policies().await.unwrap();
    assert!(names.contains(&"default".to_owned()) && names.contains(&"root".to_owned()));
    sys.delete_policy("p1").await.unwrap();
    for e in [
        sys.write_policy("", "x").await.unwrap_err(),
        sys.read_policy("").await.unwrap_err(),
        sys.delete_policy("").await.unwrap_err(),
    ] {
        assert_eq!(e.code(), ErrorCode::Validation);
    }
}

#[tokio::test]
async fn mounts_and_auth_methods() {
    let server = MockServer::start().await;
    on(&server, "GET", "/v1/sys/mounts", "mounts.list").await;
    on(&server, "GET", "/v1/sys/auth", "auth.list").await;
    once(&server, "POST", "/v1/sys/mounts/tmp", "mounts.enable").await;
    on(
        &server,
        "POST",
        "/v1/sys/mounts/tmp",
        "mounts.enable_conflict",
    )
    .await;
    on(&server, "DELETE", "/v1/sys/mounts/tmp", "mounts.disable").await;
    on(&server, "POST", "/v1/sys/auth/ar", "auth.enable").await;
    on(&server, "DELETE", "/v1/sys/auth/ar", "auth.disable").await;
    on(
        &server,
        "GET",
        "/v1/sys/internal/ui/mounts/tmp",
        "kv.detect_v1",
    )
    .await;
    let c = client(&server);
    let sys = c.sys();
    let mounts = sys.list_mounts().await.unwrap();
    assert_eq!(mounts["secret/"].mount_type, "kv");
    assert_eq!(mounts["secret/"].options["version"], "2");
    assert!(mounts.contains_key("transit/") && mounts.contains_key("sys/"));
    assert!(!mounts["secret/"].uuid.is_empty());
    let auths = sys.list_auth_methods().await.unwrap();
    assert_eq!(auths["approle/"].mount_type, "approle");
    assert!(auths.contains_key("token/"));

    // detection is cached, enabling or disabling a mount forgets it
    assert_eq!(c.detect_kv_version("tmp").await.unwrap(), 1);
    let opts = MountOptions {
        description: Some("tmp kv".into()),
        options: BTreeMap::from([("version".to_owned(), "2".to_owned())]),
        default_lease_ttl: Some(Duration::from_secs(60)),
        max_lease_ttl: Some(Duration::from_secs(120)),
        local: true,
        seal_wrap: true,
    };
    sys.enable_secrets_engine("/tmp/", "kv", Some(&opts))
        .await
        .unwrap();
    assert_eq!(
        sent(&server, "/v1/sys/mounts/tmp").await[0],
        json!({"type": "kv", "description": "tmp kv", "options": {"version": "2"},
               "config": {"default_lease_ttl": "60s", "max_lease_ttl": "120s"}, "local": true, "seal_wrap": true})
    );
    c.kv_at("tmp").await.unwrap();
    assert_eq!(
        requests(&server, "/v1/sys/internal/ui/mounts/tmp")
            .await
            .len(),
        2
    );
    let err = sys
        .enable_secrets_engine("tmp", "kv", None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    assert!(err.message().contains("already in use"));
    assert_eq!(
        sent(&server, "/v1/sys/mounts/tmp").await[1],
        json!({"type": "kv"})
    );
    sys.disable_secrets_engine("tmp").await.unwrap();
    sys.enable_auth_method("ar", "approle", None).await.unwrap();
    sys.disable_auth_method("ar").await.unwrap();
    for e in [
        sys.enable_secrets_engine("", "kv", None).await.unwrap_err(),
        sys.enable_secrets_engine("x", "", None).await.unwrap_err(),
        sys.disable_secrets_engine("/").await.unwrap_err(),
        sys.enable_auth_method("x", "", None).await.unwrap_err(),
        sys.enable_auth_method("", "approle", None)
            .await
            .unwrap_err(),
        sys.disable_auth_method("").await.unwrap_err(),
    ] {
        assert_eq!(e.code(), ErrorCode::Validation);
    }
    // a restricted token cannot list mounts; an odd body is an empty map
    let server = MockServer::start().await;
    on(&server, "GET", "/v1/sys/mounts", "capabilities.forbidden").await;
    on_reply(
        &server,
        "GET",
        "/v1/sys/auth",
        json(200, json!({"data": "x"})),
    )
    .await;
    let c = client(&server);
    assert_eq!(
        c.sys().list_mounts().await.unwrap_err().code(),
        ErrorCode::PermissionDenied
    );
    assert!(c.sys().list_auth_methods().await.unwrap().is_empty());
}

#[tokio::test]
async fn approle_admin() {
    let server = MockServer::start().await;
    on(
        &server,
        "POST",
        "/v1/auth/ar/role/r1",
        "approle.create_role",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/auth/approle/role/r1",
        "approle.create_role",
    )
    .await;
    on_reply(
        &server,
        "GET",
        "/v1/auth/approle/role",
        json(200, json!({"data": {"keys": ["zeta", "alpha"]}})),
    )
    .await;
    on_list(&server, "/v1/auth/ar/role", "approle.list_roles").await;
    on(
        &server,
        "DELETE",
        "/v1/auth/approle/role/r1",
        "policy.delete",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/auth/ar/role/r1/role-id",
        "approle.read_role_id",
    )
    .await;
    on(
        &server,
        "GET",
        "/v1/auth/approle/role/missing/role-id",
        "policy.read_missing",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/auth/ar/role/r1/secret-id",
        "approle.generate_secret_id",
    )
    .await;
    let c = client(&server);
    let sys = c.sys();
    let opts = AppRoleOptions {
        mount: Some("ar".into()),
        token_policies: vec!["sdk-app".into()],
        token_ttl: Some(Duration::from_secs(3600)),
        token_max_ttl: Some(Duration::from_secs(7200)),
        token_num_uses: 2,
        token_type: Some("service".into()),
        secret_id_ttl: Some(Duration::from_secs(600)),
        secret_id_num_uses: 1,
        bind_secret_id: Some(true),
    };
    sys.create_app_role("r1", &opts).await.unwrap();
    assert_eq!(
        sent(&server, "/v1/auth/ar/role/r1").await[0],
        json!({"token_policies": ["sdk-app"], "token_ttl": "3600s", "token_max_ttl": "7200s",
               "secret_id_ttl": "600s", "token_num_uses": 2, "token_type": "service",
               "secret_id_num_uses": 1, "bind_secret_id": true})
    );
    sys.create_app_role("r1", &AppRoleOptions::default())
        .await
        .unwrap();
    assert_eq!(
        sys.list_app_roles(None).await.unwrap(),
        vec!["alpha", "zeta"]
    );
    assert_eq!(
        sys.list_app_roles(Some("ar")).await.unwrap(),
        vec!["rt-role-RUN", "sdk-app"]
    );
    sys.delete_app_role("r1", None).await.unwrap();
    let id = sys.read_role_id("r1", Some("ar")).await.unwrap();
    assert_eq!(id, "REDACTED");
    assert_eq!(
        sys.read_role_id("missing", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    let sid = sys
        .generate_secret_id(
            "r1",
            &SecretIdOptions {
                mount: Some("ar".into()),
                metadata: BTreeMap::from([("purpose".to_owned(), "sdk".to_owned())]),
                ttl: Some(Duration::from_secs(60)),
                num_uses: 1,
                cidr_list: vec!["10.0.0.0/8".into()],
            },
        )
        .await
        .unwrap();
    assert_eq!(sid.num_uses, 1);
    assert_eq!(sid.ttl, Duration::ZERO);
    assert!(!sid.secret_id.is_empty());
    assert!(format!("{sid:?}").contains("[REDACTED]"));
    assert_eq!(
        sent(&server, "/v1/auth/ar/role/r1/secret-id").await[0],
        json!({"metadata": "{\"purpose\":\"sdk\"}", "ttl": "60s", "num_uses": 1, "cidr_list": ["10.0.0.0/8"]})
    );
    for e in [
        sys.create_app_role("", &opts).await.unwrap_err(),
        sys.delete_app_role("", None).await.unwrap_err(),
        sys.read_role_id("", None).await.unwrap_err(),
        sys.generate_secret_id("", &SecretIdOptions::default())
            .await
            .unwrap_err(),
    ] {
        assert_eq!(e.code(), ErrorCode::Validation);
    }
}

#[tokio::test]
async fn wrap_lookup_unwrap() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/wrap"))
        .and(header("x-vault-wrap-ttl", "60s"))
        .respond_with(reply("wrapping.wrap"))
        .mount(&server)
        .await;
    on_reply(
        &server,
        "POST",
        "/v1/sys/wrapping/wrap",
        json(
            400,
            json!({"errors": ["endpoint requires response wrapping to be used"]}),
        ),
    )
    .await;
    once(
        &server,
        "POST",
        "/v1/sys/wrapping/lookup",
        "wrapping.lookup",
    )
    .await;
    on(
        &server,
        "POST",
        "/v1/sys/wrapping/lookup",
        "wrapping.unwrap_again",
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/unwrap"))
        .and(header("x-vault-token", "wrap-token-1"))
        .respond_with(reply("wrapping.unwrap"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    on(
        &server,
        "POST",
        "/v1/sys/wrapping/unwrap",
        "wrapping.unwrap_again",
    )
    .await;
    let c = client(&server);
    let w = c.wrapping();
    let info = w
        .wrap(
            json!({"secret": "wrapped", "n": 1}),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert_eq!(info.ttl, Duration::from_secs(300));
    assert_eq!(info.creation_path, "sys/wrapping/wrap");
    assert!(info.creation_time.is_some() && !info.token.is_empty());
    assert!(format!("{info:?}").contains("token: [REDACTED]"));
    assert_eq!(
        sent(&server, "/v1/sys/wrapping/wrap").await[0],
        json!({"secret": "wrapped", "n": 1})
    );
    let l = w.lookup_wrapping("wrap-token-1").await.unwrap();
    assert_eq!(l.creation_path, "sys/wrapping/wrap");
    assert_eq!(l.creation_ttl, Duration::from_secs(300));
    assert!(l.creation_time.is_some());
    let r = w.unwrap("wrap-token-1").await.unwrap();
    assert_eq!(r.data["foo"], "bar");
    assert!(r.auth.is_none() && r.wrap_info.is_none());
    assert!(!r.request_id.is_empty());
    assert!(!format!("{r:?}").contains("\"bar\""));
    let err = w.unwrap("wrap-token-1").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    assert!(!err.message().contains("wrap-token-1"));
    assert_eq!(
        w.lookup_wrapping("wrap-token-1").await.unwrap_err().code(),
        ErrorCode::Validation
    );
    w.wrap(serde_json::Value::Null, Duration::from_millis(1))
        .await
        .unwrap_err();
    for e in [
        w.wrap(json!({}), Duration::ZERO).await.unwrap_err(),
        w.wrap(json!([1]), Duration::from_secs(1))
            .await
            .unwrap_err(),
        w.unwrap("").await.unwrap_err(),
        w.lookup_wrapping("").await.unwrap_err(),
    ] {
        assert_eq!(e.code(), ErrorCode::Validation);
    }
    // a wrapped login response carries auth; a wrap answer without wrap_info is an error
    let server = MockServer::start().await;
    on_reply(
        &server,
        "POST",
        "/v1/sys/wrapping/unwrap",
        json(200, json!({"auth": {"client_token": "child-token-1", "lease_duration": 60}, "wrap_info": {"token": "inner-wrap", "ttl": 5}})),
    )
    .await;
    on_reply(
        &server,
        "POST",
        "/v1/sys/wrapping/wrap",
        json(200, json!({"data": null})),
    )
    .await;
    let w = client(&server).wrapping();
    let r = w.unwrap("t-1234").await.unwrap();
    assert_eq!(r.auth.unwrap().lease_duration, Duration::from_secs(60));
    assert_eq!(r.wrap_info.unwrap().ttl, Duration::from_secs(5));
    assert_eq!(
        w.wrap(json!({}), Duration::from_secs(1))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Unavailable
    );
}

#[cfg(feature = "testing")]
#[tokio::test]
async fn operator_init_unseal_seal() {
    use sdk::testing::{self, InitOptions};
    let server = MockServer::start().await;
    on(&server, "GET", "/v1/sys/init", "init.status").await;
    once(&server, "PUT", "/v1/sys/init", "init.init").await;
    on(&server, "PUT", "/v1/sys/init", "init.again").await;
    once(&server, "PUT", "/v1/sys/unseal", "unseal.unseal").await;
    on(&server, "PUT", "/v1/sys/unseal", "unseal.bad_key").await;
    on(&server, "PUT", "/v1/sys/seal", "seal.seal").await;
    on(&server, "GET", "/v1/sys/health", "health").await;
    let c = client(&server);
    assert!(!testing::init_status(&c).await.unwrap());
    let init = testing::init(&c, &InitOptions::default()).await.unwrap();
    assert_eq!((init.keys.len(), init.keys_base64.len()), (1, 1));
    assert!(init.recovery_keys.is_empty() && init.recovery_keys_base64.is_empty());
    assert!(!init.root_token.is_empty());
    assert!(!format!("{init:?}").contains("<redacted>"));
    assert_eq!(
        sent(&server, "/v1/sys/init").await[0],
        json!({"secret_shares": 1, "secret_threshold": 1})
    );
    let err = testing::init(
        &c,
        &InitOptions {
            recovery_shares: Some(3),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    assert!(err.message().contains("already initialized"));
    assert_eq!(
        sent(&server, "/v1/sys/init").await[1],
        json!({"recovery_shares": 3, "recovery_threshold": 1})
    );
    let st = testing::unseal(&c, "abcd1234").await.unwrap();
    assert!(!st.sealed && st.initialized);
    assert_eq!(st.seal_type, "shamir");
    assert_eq!(
        testing::unseal(&c, "zz").await.unwrap_err().code(),
        ErrorCode::Validation
    );
    assert_eq!(
        testing::unseal(&c, "").await.unwrap_err().code(),
        ErrorCode::Validation
    );
    let _ = testing::unseal_reset(&c).await;
    assert_eq!(
        sent(&server, "/v1/sys/unseal").await.last().unwrap(),
        &json!({"reset": true})
    );
    testing::seal(&c).await.unwrap();
    let h = testing::wait_for_active(&c, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(h.state, "active");

    // never active: TIMEOUT; no root token: UNAVAILABLE
    let server = MockServer::start().await;
    on(&server, "GET", "/v1/sys/health", "init.health_sealed").await;
    on_reply(
        &server,
        "PUT",
        "/v1/sys/init",
        json(200, json!({"keys": []})),
    )
    .await;
    let c = client(&server);
    assert_eq!(
        testing::wait_for_active(&c, Duration::from_millis(300))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Timeout
    );
    assert_eq!(
        testing::init(&c, &InitOptions::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Unavailable
    );
}
