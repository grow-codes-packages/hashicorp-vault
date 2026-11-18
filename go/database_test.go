package vault

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestDatabase(t *testing.T) {
	m := newMockVault(t).
		fixture("POST", "/v1/database/config/pg", "database.configure_connection").
		fixture("GET", "/v1/database/config/pg", "database.read_connection").
		noContent("DELETE", "/v1/database/config/pg").
		fixture("POST", "/v1/database/roles/ro", "database.create_role").
		fixture("GET", "/v1/database/roles/ro", "database.read_role").
		noContent("DELETE", "/v1/database/roles/ro").
		fixture("GET", "/v1/database/creds/ro", "database.get_credentials").
		fixture("GET", "/v1/database/creds/unknown", "database.get_credentials_missing_role").
		fixture("POST", "/v1/database/config/bad", "database.configure_connection_bad")
	c := newVaultClient(t, m, nil)
	db := c.Database("")
	ctx := t.Context()
	if db.Mount() != "database" {
		t.Fatal("mount")
	}
	err := db.ConfigureConnection(ctx, "pg", DatabaseConnectionConfig{
		PluginName: "postgresql-database-plugin", ConnectionURL: "postgresql://{{username}}:{{password}}@pg:5432/app",
		Username: "postgres", Password: NewSecret("pg-admin-pw"), AllowedRoles: []string{"ro"}, VerifyConnection: Ptr(true),
		Extra: map[string]any{"max_open_connections": 4},
	})
	b := m.last("POST", "/v1/database/config/pg").JSON(t)
	if err != nil || b["password"] != "pg-admin-pw" || b["verify_connection"] != true || b["max_open_connections"] != float64(4) || b["plugin_name"] == nil {
		t.Fatalf("configure %v %v", b, err)
	}
	if cfg, err := db.ReadConnection(ctx, "pg"); err != nil || cfg["plugin_name"] == nil {
		t.Fatalf("read connection %v %v", cfg, err)
	}
	err = db.CreateRole(ctx, "ro", DatabaseRoleConfig{
		DBName: "pg", CreationStatements: []string{"CREATE ROLE"}, RevocationStatements: []string{"DROP"},
		RollbackStatements: []string{"RB"}, RenewStatements: []string{"RN"}, DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour,
	})
	b = m.last("POST", "/v1/database/roles/ro").JSON(t)
	if err != nil || b["default_ttl"] != "3600s" || b["max_ttl"] != "7200s" || b["db_name"] != "pg" || b["renew_statements"] == nil {
		t.Fatalf("create role %v %v", b, err)
	}
	role, err := db.ReadRole(ctx, "ro")
	if err != nil || role.DefaultTTL != 5*time.Minute || role.MaxTTL != 10*time.Minute || len(role.CreationStatements) != 1 {
		t.Fatalf("read role %+v %v", role, err)
	}
	lease, err := db.GetCredentials(ctx, "ro")
	if err != nil || !strings.HasPrefix(lease.ID, "database/creds/") || !lease.Renewable || lease.Duration != 10*time.Minute ||
		lease.Username == "" || lease.Password.Reveal() != "REDACTED" || lease.Data["password"] != nil || lease.ExpiresAt().IsZero() {
		t.Fatalf("creds %+v %v", lease, err)
	}
	if strings.Contains(fmt.Sprintf("%+v", lease), "Password:REDACTED") {
		t.Fatal("password must print redacted")
	}
	if (&Lease{}).ExpiresAt() != (time.Time{}) {
		t.Fatal("non-expiring lease")
	}
	if err := db.DeleteRole(ctx, "ro"); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteConnection(ctx, "pg"); err != nil {
		t.Fatal(err)
	}
	_, err = db.GetCredentials(ctx, "unknown")
	wantCode(t, err, ErrorCodeValidation)
	wantCode(t, db.ConfigureConnection(ctx, "bad", DatabaseConnectionConfig{}), ErrorCodeValidation)
	wantCode(t, db.ConfigureConnection(ctx, "", DatabaseConnectionConfig{}), ErrorCodeValidation)
	wantCode(t, db.CreateRole(ctx, "", DatabaseRoleConfig{}), ErrorCodeValidation)
	_, err = db.GetCredentials(ctx, "")
	wantCode(t, err, ErrorCodeValidation)
	_, err = db.ReadRole(ctx, "missing")
	wantCode(t, err, ErrorCodeNotFound)
	m.json("GET", "/v1/database/creds/odd", 200, map[string]any{"data": []int{1}})
	_, err = db.GetCredentials(ctx, "odd")
	wantCode(t, err, ErrorCodeUnavailable)
	_, err = db.GetCredentials(ctx, "missing")
	wantCode(t, err, ErrorCodeNotFound)
}

func TestLeaseManager(t *testing.T) {
	m := newMockVault(t).
		fixture("PUT", "/v1/sys/leases/renew", "lease.renew").
		fixture("PUT", "/v1/sys/leases/revoke", "lease.revoke").
		fixture("PUT", "/v1/sys/leases/lookup", "lease.lookup").
		noContent("PUT", "/v1/sys/leases/revoke-prefix/database/creds/ro")
	c := newVaultClient(t, m, nil)
	lm := c.LeaseManager()
	ctx := t.Context()
	info, err := lm.Renew(ctx, "database/creds/ro/abc", 15*time.Minute)
	if err != nil || info.Duration != 15*time.Minute || info.ID == "" || info.Capped() || m.last("PUT", "/v1/sys/leases/renew").JSON(t)["increment"] != "900s" {
		t.Fatalf("renew %+v %v", info, err)
	}
	lk, err := lm.Lookup(ctx, "database/creds/ro/abc")
	if err != nil || lk.Path != "" || lk.ID == "" || lk.TTL != 599*time.Second || lk.ExpireTime.IsZero() || !lk.LastRenewal.IsZero() {
		t.Fatalf("lookup %+v %v", lk, err)
	}
	if err := lm.Revoke(ctx, "database/creds/ro/abc"); err != nil {
		t.Fatal(err)
	}
	if err := lm.RevokePrefix(ctx, "/database/creds/ro/"); err != nil {
		t.Fatal(err)
	}
	_, err = lm.Renew(ctx, "", 0)
	wantCode(t, err, ErrorCodeValidation)
	wantCode(t, lm.Revoke(ctx, ""), ErrorCodeValidation)
	wantCode(t, lm.RevokePrefix(ctx, ""), ErrorCodeValidation)
	_, err = lm.Lookup(ctx, "")
	wantCode(t, err, ErrorCodeValidation)

	t.Run("errors and capping", func(t *testing.T) {
		m := newMockVault(t).
			fixture("PUT", "/v1/sys/leases/renew", "lease.renew_over_max").
			fixture("PUT", "/v1/sys/leases/renew", "lease.renew_invalid").
			fixture("PUT", "/v1/sys/leases/lookup", "lease.lookup_revoked")
		lm := newVaultClient(t, m, nil).LeaseManager()
		info, err := lm.Renew(t.Context(), "l1", 100*time.Hour)
		if err != nil || !info.Capped() || info.Duration != time.Hour {
			t.Fatalf("capped %+v %v", info, err)
		}
		_, err = lm.Renew(t.Context(), "l1", 0)
		wantCode(t, err, ErrorCodeValidation)
		_, err = lm.Lookup(t.Context(), "l1")
		wantCode(t, err, ErrorCodeValidation)
		m.json("PUT", "/v1/sys/leases/renew-id", 200, map[string]any{"lease_duration": 5})
	})
}

func leaseReply(ttl int, renewable bool, warnings ...string) map[string]any {
	return map[string]any{"lease_id": "", "renewable": renewable, "lease_duration": ttl, "warnings": warnings}
}

func TestManagedLease(t *testing.T) {
	lease := func(ttl time.Duration, renewable bool) *Lease {
		return &Lease{ID: "database/creds/ro/x", Renewable: renewable, Duration: ttl}
	}
	t.Run("renews until capped then expires once", func(t *testing.T) {
		m := newMockVault(t).
			json("PUT", "/v1/sys/leases/renew", 200, leaseReply(3600, true)).
			json("PUT", "/v1/sys/leases/renew", 200, leaseReply(1800, true, `TTL of "100h" exceeded the effective max_ttl of "2h"; TTL value is capped accordingly`))
		lm := newVaultClient(t, m, nil).LeaseManager()
		var renews, expires int
		ml := lm.Manage(lease(time.Hour, true), &ManageOptions{
			Clock: newFakeClock(), OnRenew: func(*LeaseInfo) { renews++ }, OnExpire: func(*Lease) { expires++ },
		})
		waitDone(t, ml.Done())
		if renews != 2 || expires != 1 || ml.Lease().ID == "" {
			t.Fatalf("renews=%d expires=%d", renews, expires)
		}
	})
	t.Run("increment above grant counts as capped", func(t *testing.T) {
		m := newMockVault(t).json("PUT", "/v1/sys/leases/renew", 200, leaseReply(60, true))
		lm := newVaultClient(t, m, nil).LeaseManager()
		expired := false
		ml := lm.Manage(lease(time.Minute, true), &ManageOptions{Increment: time.Hour, Clock: newFakeClock(), OnExpire: func(*Lease) { expired = true }})
		waitDone(t, ml.Done())
		if !expired || m.count("PUT", "/v1/sys/leases/renew") != 1 {
			t.Fatal("capped by increment")
		}
	})
	t.Run("rejected renewal expires", func(t *testing.T) {
		m := newMockVault(t).errors("PUT", "/v1/sys/leases/renew", 400, "lease not found")
		lm := newVaultClient(t, m, nil).LeaseManager()
		var errs, expires int
		ml := lm.Manage(lease(time.Minute, true), &ManageOptions{Clock: newFakeClock(), OnError: func(error) { errs++ }, OnExpire: func(*Lease) { expires++ }})
		waitDone(t, ml.Done())
		if errs != 1 || expires != 1 {
			t.Fatalf("errs=%d expires=%d", errs, expires)
		}
	})
	t.Run("retryable errors until expiry", func(t *testing.T) {
		m := newMockVault(t).errors("PUT", "/v1/sys/leases/renew", 503, "sealed")
		lm := newVaultClient(t, m, nil).LeaseManager()
		var errs, expires int
		ml := lm.Manage(lease(time.Minute, true), &ManageOptions{Clock: newFakeClock(), OnError: func(error) { errs++ }, OnExpire: func(*Lease) { expires++ }})
		waitDone(t, ml.Done())
		if errs < 2 || expires != 1 {
			t.Fatalf("errs=%d expires=%d", errs, expires)
		}
	})
	t.Run("not renewable waits for expiry", func(t *testing.T) {
		lm := newVaultClient(t, newMockVault(t), nil).LeaseManager()
		expired := false
		l := lease(time.Minute, false)
		l.IssuedAt = time.Now()
		ml := lm.Manage(l, &ManageOptions{Clock: newFakeClock(), OnExpire: func(*Lease) { expired = true }})
		waitDone(t, ml.Done())
		if !expired {
			t.Fatal("expire")
		}
	})
	t.Run("stop, revoke and close", func(t *testing.T) {
		m := newMockVault(t).noContent("PUT", "/v1/sys/leases/revoke")
		c := newVaultClient(t, m, nil)
		lm := c.LeaseManager()
		a := lm.Manage(lease(time.Minute, true), &ManageOptions{Clock: blockClock{}})
		b := lm.Manage(lease(0, false), nil)
		other := &Lease{ID: "other", Renewable: true, Duration: time.Minute}
		d := lm.Manage(other, &ManageOptions{Clock: blockClock{}})
		if err := lm.Revoke(t.Context(), "database/creds/ro/x"); err != nil {
			t.Fatal(err)
		}
		waitDone(t, a.Done())
		waitDone(t, b.Done())
		d.Stop()
		waitDone(t, d.Done())
		e := lm.Manage(other, &ManageOptions{Clock: blockClock{}})
		_ = c.Close()
		waitDone(t, e.Done())
		f := lm.Manage(other, nil)
		waitDone(t, f.Done())
	})
}
