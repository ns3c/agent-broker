package jira

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateIsIdempotent(t *testing.T) {
	s := &store{apiKey: "k", issues: map[string][]Issue{}, idem: map[string]map[string]int{}}
	create := func(tenant, idemKey string) (int, Issue) {
		r := httptest.NewRequest("POST", "/rest/api/issue", strings.NewReader(`{"title":"t"}`))
		r.Header.Set("Authorization", "Bearer k")
		r.Header.Set("X-Tenant", tenant)
		if idemKey != "" {
			r.Header.Set("Idempotency-Key", idemKey)
		}
		w := httptest.NewRecorder()
		s.create(w, r)
		var out Issue
		_ = json.NewDecoder(w.Body).Decode(&out)
		return w.Code, out
	}

	code, first := create("t1", "run:a")
	if code != http.StatusCreated || first.Replayed {
		t.Fatalf("first create: code %d replayed %v", code, first.Replayed)
	}
	code, retry := create("t1", "run:a")
	if code != http.StatusOK || !retry.Replayed || retry.Key != first.Key {
		t.Fatalf("retry: code %d replayed %v key %s, want 200 true %s", code, retry.Replayed, retry.Key, first.Key)
	}
	if _, other := create("t1", "run:b"); other.Key == first.Key {
		t.Fatal("different key must create a new ticket")
	}
	if _, otherTenant := create("t2", "run:a"); otherTenant.Replayed {
		t.Fatal("keys must not match across tenants")
	}
	if n := len(s.issues["t1"]); n != 2 {
		t.Fatalf("tenant t1 has %d tickets, want 2", n)
	}
}
