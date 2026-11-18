package vault

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestWithNamespace(t *testing.T) {
	m := newMockVault(t).
		fixture("GET", "/v1/secret/data/app/RUN/login", "namespace.header_kv").
		fixture("GET", "/v1/sys/health", "health.namespace_header").
		fixture("POST", "/v1/auth/approle/login", "approle.login")
	c := newVaultClient(t, m, nil)
	ctx := t.Context()

	ns := c.WithNamespace("/team-a/")
	if ns.Namespace() != "team-a" || c.Namespace() != "" || ns.Config().Namespace != "team-a" {
		t.Fatalf("namespace %q parent %q", ns.Namespace(), c.Namespace())
	}
	if _, err := ns.KVv2("secret").Read(ctx, "app/RUN/login", nil); err != nil {
		t.Fatal(err)
	}
	r := m.last("GET", "/v1/secret/data/app/RUN/login")
	if r.Header.Get("X-Vault-Namespace") != "team-a" || r.Header.Get("X-Vault-Token") != testToken {
		t.Fatalf("view headers %v", r.Header)
	}
	if hs, err := ns.Health(ctx); err != nil || !hs.Healthy || m.last("GET", "/v1/sys/health").Header.Get("X-Vault-Namespace") != "team-a" {
		t.Fatalf("view health %+v %v", hs, err)
	}
	// The parent is unchanged.
	if _, err := c.KVv2("secret").Read(ctx, "app/RUN/login", nil); err != nil {
		t.Fatal(err)
	}
	if h := m.last("GET", "/v1/secret/data/app/RUN/login").Header.Get("X-Vault-Namespace"); h != "" {
		t.Fatalf("parent sent namespace %q", h)
	}
	// A login on the view changes only the view's token.
	if _, err := ns.Auth().Login(ctx, NewAppRoleAuth("role", "secret")); err != nil {
		t.Fatal(err)
	}
	if ns.Token().Reveal() != "REDACTED" || c.Token().Reveal() != testToken {
		t.Fatal("view token must be independent of the parent token")
	}
	// Nested views replace the namespace; "" is the root namespace.
	root := ns.WithNamespace("")
	if _, err := root.KVv2("").Read(ctx, "app/RUN/login", nil); err != nil {
		t.Fatal(err)
	}
	if h := m.last("GET", "/v1/secret/data/app/RUN/login").Header.Get("X-Vault-Namespace"); h != "" {
		t.Fatalf("root view sent namespace %q", h)
	}

	t.Run("invalid namespace", func(t *testing.T) {
		bad := c.WithNamespace("a b")
		if _, err := bad.Ping(ctx); !errors.Is(err, ErrConfig) {
			t.Fatalf("ping: %v", err)
		}
		if _, err := bad.Health(ctx); !errors.Is(err, ErrConfig) {
			t.Fatalf("health: %v", err)
		}
	})
	t.Run("close", func(t *testing.T) {
		v := c.WithNamespace("team-b")
		if err := v.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := v.Ping(ctx); !errors.Is(err, ErrCancelled) {
			t.Fatalf("closed view: %v", err)
		}
		// Closing a view keeps the shared connections of the parent.
		if _, err := c.KVv2("secret").Read(ctx, "app/RUN/login", nil); err != nil {
			t.Fatalf("parent after view close: %v", err)
		}
		v2 := c.WithNamespace("team-c")
		_ = c.Close()
		if !v2.isClosed() {
			t.Fatal("closing the parent closes its views")
		}
	})
}

func TestCapabilities(t *testing.T) {
	m := newMockVault(t).
		fixture("POST", "/v1/sys/capabilities-self", "capabilities_self.plural").
		fixture("POST", "/v1/sys/capabilities-self", "capabilities_self.single").
		fixture("POST", "/v1/sys/capabilities-self", "capabilities_self.root").
		fixture("POST", "/v1/sys/capabilities", "capabilities.token")
	c := newVaultClient(t, m, nil)
	ctx := t.Context()

	caps, err := c.Sys().CapabilitiesSelf(ctx, "secret/data/app/RUN/x", "/secret/data/denied/RUN")
	if err != nil {
		t.Fatal(err)
	}
	want := Capabilities{
		"secret/data/app/RUN/x":  {"create", "delete", "patch", "read", "update"},
		"secret/data/denied/RUN": {"deny"},
	}
	if !reflect.DeepEqual(caps, want) {
		t.Fatalf("caps %v", caps)
	}
	if b := m.last("POST", "/v1/sys/capabilities-self").JSON(t); !reflect.DeepEqual(b["paths"], []any{"secret/data/app/RUN/x", "secret/data/denied/RUN"}) {
		t.Fatalf("body %v", b)
	}
	if !caps.Allows("secret/data/app/RUN/x", CapabilityRead) || caps.Allows("secret/data/app/RUN/x", CapabilitySudo) ||
		caps.Allows("secret/data/denied/RUN", CapabilityRead) || caps.Allows("other", CapabilityRead) {
		t.Fatal("Allows")
	}

	single, err := c.Sys().CapabilitiesSelf(ctx, "transit/encrypt/sdk-aes")
	if err != nil || !reflect.DeepEqual(single, Capabilities{"transit/encrypt/sdk-aes": {"update"}}) {
		t.Fatalf("single %v %v", single, err)
	}
	rootCaps, err := c.Sys().CapabilitiesSelf(ctx, "sys/mounts", "not-in-response")
	if err != nil || !rootCaps.Allows("sys/mounts", CapabilityDelete) || len(rootCaps["not-in-response"]) != 0 {
		t.Fatalf("root %v %v", rootCaps, err)
	}

	tokenCaps, err := c.Sys().Capabilities(ctx, "other-token-123", "secret/data/app/RUN/x", "sys/mounts")
	if err != nil || !tokenCaps.Allows("secret/data/app/RUN/x", CapabilityCreate) || tokenCaps.Allows("sys/mounts", CapabilityRead) {
		t.Fatalf("token caps %v %v", tokenCaps, err)
	}
	if b := m.last("POST", "/v1/sys/capabilities").JSON(t); b["token"] != "other-token-123" {
		t.Fatalf("body %v", b)
	}

	t.Run("errors", func(t *testing.T) {
		m := newMockVault(t).fixture("POST", "/v1/sys/capabilities", "capabilities.forbidden")
		c := newVaultClient(t, m, nil)
		_, err := c.Sys().Capabilities(ctx, "other-token-123", "sys/mounts")
		wantCode(t, err, ErrorCodePermissionDenied)
		if strings.Contains(err.Error(), "other-token-123") {
			t.Fatal("token leaked")
		}
		_, err = c.Sys().Capabilities(ctx, "", "x")
		wantCode(t, err, ErrorCodeValidation)
		_, err = c.Sys().CapabilitiesSelf(ctx)
		wantCode(t, err, ErrorCodeValidation)
		_, err = c.Sys().CapabilitiesSelf(ctx, "/", "")
		wantCode(t, err, ErrorCodeValidation)
		if len(m.requests()) != 1 {
			t.Fatal("argument errors must not send requests")
		}
	})
}

func TestVaultLoginAndRetryRules(t *testing.T) {
	m := newMockVault(t).
		fixture("POST", "/v1/auth/userpass/login/sdk-user", "userpass.login_bad").
		errors("POST", "/v1/auth/approle/login", 403, "1 error occurred:\n\t* permission denied\n\n").
		errors("POST", "/v1/auth/jwt/login", 401, "unauthorized").
		fixture("GET", "/v1/database/creds/sdk-readonly", "error.bad_json").
		fixture("GET", "/v1/auth/token/lookup-self", "sealed.request")
	c := newTestClient(t, m.URL, nil) // fastRetry(3)
	ctx := t.Context()
	for _, method := range []AuthMethod{NewUserpassAuth("sdk-user", "bad-pw-1"), NewAppRoleAuth("r", "s"), NewJWTAuth("r", "j")} {
		if _, err := c.Auth().Login(ctx, method); CodeOf(err) != ErrorCodeAuthentication {
			t.Fatalf("%T: %v", method, err)
		}
	}
	// Dynamic credentials create a database user per call: a 500 is never retried.
	_, err := c.Database("").GetCredentials(ctx, "sdk-readonly")
	wantCode(t, err, ErrorCodeUnavailable)
	if n := m.count("GET", "/v1/database/creds/sdk-readonly"); n != 1 {
		t.Fatalf("creds sent %d times", n)
	}
	// A sealed server (503) is retryable.
	_, err = c.Auth().LookupSelf(ctx)
	if CodeOf(err) != ErrorCodeUnavailable || !isRetryable(err) || m.count("GET", "/v1/auth/token/lookup-self") != 4 {
		t.Fatalf("sealed: %v (%d attempts)", err, m.count("GET", "/v1/auth/token/lookup-self"))
	}
}
