package keys

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"

	"runic/internal/auth"
	"runic/internal/db"
	"runic/internal/store"
	"runic/internal/testutil"
)

// resetTestAuthState clears the process-global JWT state touched by the key
// handlers so tests in this package remain isolated.
func resetTestAuthState() {
	auth.SetSettingsStore(nil)
	auth.JwtKeyMu.Lock()
	auth.JwtKey = nil
	auth.JwtPrevKey = nil
	auth.JwtKeyMu.Unlock()
}

func setupRouter(handler *Handler) *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/api/v1/setup-keys", handler.ListKeys).Methods("GET")
	router.HandleFunc("/api/v1/setup-keys/{type}", handler.CreateKey).Methods("POST")
	router.HandleFunc("/api/v1/setup-keys/{type}", handler.DeleteKey).Methods("DELETE")
	return router
}

func TestListKeys_Empty(t *testing.T) {
	testDB, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ks, err := store.NewKeyStore(testDB)
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	handler := NewHandler(ks)
	router := setupRouter(handler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/setup-keys", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("ListKeys() status = %d, want %d", rec.Code, http.StatusOK)
	}

	var keys []map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&keys); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(keys) != 2 {
		t.Errorf("ListKeys() returned %d keys, want 2", len(keys))
	}

	for _, k := range keys {
		if exists, ok := k["exists"].(bool); !ok || exists {
			t.Errorf("key %v should not exist", k["type"])
		}
	}
}

func TestCreateKey_Success(t *testing.T) {
	testDB, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ks, err := store.NewKeyStore(testDB)
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	handler := NewHandler(ks)
	router := setupRouter(handler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup-keys/jwt-secret", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("CreateKey() status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if exists, ok := resp["exists"].(bool); !ok || !exists {
		t.Error("CreateKey() should return exists=true")
	}

	// Verify key is stored in system_config table
	var value string
	if err := testDB.QueryRow("SELECT value FROM system_config WHERE key = ?", "jwt_secret").Scan(&value); err != nil {
		t.Fatalf("jwt_secret not found in system_config: %v", err)
	}
	if len(value) == 0 {
		t.Error("jwt_secret value is empty")
	}

	// The first key creation records the one-time bootstrap marker so a later
	// deletion cannot be undone by environment seeding.
	var markerCount int
	if err := testDB.QueryRow("SELECT COUNT(*) FROM system_config WHERE key = ?", db.JWTSecretsSeedMarker).Scan(&markerCount); err != nil {
		t.Fatalf("count bootstrap marker: %v", err)
	}
	if markerCount != 1 {
		t.Error("bootstrap marker should be recorded after creating a key")
	}
}

func TestCreateKey_InvalidType(t *testing.T) {
	testDB, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ks, err := store.NewKeyStore(testDB)
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	handler := NewHandler(ks)
	router := setupRouter(handler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup-keys/invalid-type", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("CreateKey() status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestDeleteKey_Success(t *testing.T) {
	testDB, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ks, err := store.NewKeyStore(testDB)
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	handler := NewHandler(ks)
	router := setupRouter(handler)

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/setup-keys/jwt-secret", nil)
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("CreateKey() failed: status = %d", createRec.Code)
	}

	// Verify key exists
	var value string
	if err := testDB.QueryRow("SELECT value FROM system_config WHERE key = ?", "jwt_secret").Scan(&value); err != nil {
		t.Fatalf("jwt_secret not found in system_config after create: %v", err)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/setup-keys/jwt-secret", nil)
	deleteRec := httptest.NewRecorder()
	router.ServeHTTP(deleteRec, deleteReq)

	if deleteRec.Code != http.StatusOK {
		t.Errorf("DeleteKey() status = %d, want %d", deleteRec.Code, http.StatusOK)
	}

	// Verify key was removed from system_config
	err = testDB.QueryRow("SELECT value FROM system_config WHERE key = ?", "jwt_secret").Scan(&value)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Error("jwt_secret should have been removed from system_config")
	}

	// The bootstrap marker must survive deletion so a restart cannot re-seed
	// the deleted key from the environment.
	var markerCount int
	if err := testDB.QueryRow("SELECT COUNT(*) FROM system_config WHERE key = ?", db.JWTSecretsSeedMarker).Scan(&markerCount); err != nil {
		t.Fatalf("count bootstrap marker: %v", err)
	}
	if markerCount != 1 {
		t.Error("bootstrap marker should remain after key deletion")
	}
}

func TestDeleteKey_NonExistent(t *testing.T) {
	testDB, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ks, err := store.NewKeyStore(testDB)
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	handler := NewHandler(ks)
	router := setupRouter(handler)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/setup-keys/jwt-secret", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("DeleteKey() status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestListKeys_AfterCreate(t *testing.T) {
	testDB, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ks, err := store.NewKeyStore(testDB)
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	handler := NewHandler(ks)
	router := setupRouter(handler)

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/setup-keys/jwt-secret", nil)
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("CreateKey() failed: status = %d", createRec.Code)
	}

	// List keys and verify jwt-secret shows exists=true
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/setup-keys", nil)
	listRec := httptest.NewRecorder()
	router.ServeHTTP(listRec, listReq)

	var keys []map[string]interface{}
	if err := json.NewDecoder(listRec.Body).Decode(&keys); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	for _, k := range keys {
		keyType := k["type"].(string)
		exists := k["exists"].(bool)
		if keyType == "jwt-secret" && !exists {
			t.Error("jwt-secret should exist after creation")
		}
		if keyType == "agent-jwt-secret" && exists {
			t.Error("agent-jwt-secret should not exist (was not created)")
		}
	}
}

// setupJWTForHandlerTest seeds a persisted signing key, wires the settings
// store, and initializes the active JWT key the same way server startup does.
func setupJWTForHandlerTest(t *testing.T, testDB *sql.DB, secret string) {
	t.Helper()
	settings := store.NewSettingsStore(testDB, nil)
	auth.SetSettingsStore(settings)
	t.Cleanup(resetTestAuthState)

	if err := settings.SetSystemConfig(context.Background(), "jwt_secret", secret); err != nil {
		t.Fatalf("seed jwt_secret: %v", err)
	}
	auth.JwtKeyMu.Lock()
	auth.JwtKey = nil
	auth.JwtPrevKey = nil
	auth.JwtKeyMu.Unlock()
	if err := auth.InitJwtKey(context.Background(), testDB); err != nil {
		t.Fatalf("InitJwtKey: %v", err)
	}
}

func activeJWTKey() string {
	auth.JwtKeyMu.RLock()
	defer auth.JwtKeyMu.RUnlock()
	return string(auth.JwtKey)
}

func TestCreateKey_RejectsPreRotationToken(t *testing.T) {
	testDB, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	const originalSecret = "original-jwt-secret-for-rotation-regression"
	setupJWTForHandlerTest(t, testDB, originalSecret)

	preRotationToken, err := auth.GenerateToken("admin", "admin", auth.TokenTypeAccess, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if _, err := auth.ValidateToken(preRotationToken); err != nil {
		t.Fatalf("pre-rotation token should validate before rotation: %v", err)
	}

	ks, err := store.NewKeyStore(testDB)
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	router := setupRouter(NewHandler(ks))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup-keys/jwt-secret", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("CreateKey() status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	if _, err := auth.ValidateToken(preRotationToken); err == nil {
		t.Fatal("pre-rotation token must be rejected after the JWT secret is replaced")
	}

	rotatedKey := activeJWTKey()
	if rotatedKey == "" {
		t.Fatal("active JWT signing key is empty after rotation")
	}
	if rotatedKey == originalSecret {
		t.Fatal("active JWT signing key was not rotated")
	}

	var storedKey string
	if err := testDB.QueryRow("SELECT value FROM system_config WHERE key = ?", "jwt_secret").Scan(&storedKey); err != nil {
		t.Fatalf("jwt_secret not found after rotation: %v", err)
	}
	if storedKey != rotatedKey {
		t.Errorf("persisted jwt_secret = %q, want active key %q", storedKey, rotatedKey)
	}
	var prevCount int
	if err := testDB.QueryRow("SELECT COUNT(*) FROM system_config WHERE key = ?", "jwt_prev_secret").Scan(&prevCount); err != nil {
		t.Fatalf("count jwt_prev_secret: %v", err)
	}
	if prevCount != 0 {
		t.Error("jwt_prev_secret should be removed so old tokens are rejected immediately")
	}
}

func TestDeleteKey_RejectsPreDeletionToken(t *testing.T) {
	testDB, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	const originalSecret = "original-jwt-secret-for-delete-regression"
	setupJWTForHandlerTest(t, testDB, originalSecret)

	preDeletionToken, err := auth.GenerateToken("admin", "admin", auth.TokenTypeAccess, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if _, err := auth.ValidateToken(preDeletionToken); err != nil {
		t.Fatalf("token should validate before deletion: %v", err)
	}

	ks, err := store.NewKeyStore(testDB)
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	router := setupRouter(NewHandler(ks))
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/setup-keys/jwt-secret", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("DeleteKey() status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if _, err := auth.ValidateToken(preDeletionToken); err == nil {
		t.Fatal("pre-deletion token must be rejected after the JWT secret is deleted")
	}
	if activeKey := activeJWTKey(); activeKey != "" {
		t.Fatalf("active JWT signing key = %q, want empty after deletion", activeKey)
	}
	auth.JwtKeyMu.RLock()
	prevKey := string(auth.JwtPrevKey)
	auth.JwtKeyMu.RUnlock()
	if prevKey != "" {
		t.Errorf("previous JWT signing key = %q, want empty after deletion", prevKey)
	}

	var storedCount int
	if err := testDB.QueryRow("SELECT COUNT(*) FROM system_config WHERE key = ?", "jwt_secret").Scan(&storedCount); err != nil {
		t.Fatalf("count jwt_secret: %v", err)
	}
	if storedCount != 0 {
		t.Error("jwt_secret should be removed from system_config")
	}
	var prevCount int
	if err := testDB.QueryRow("SELECT COUNT(*) FROM system_config WHERE key = ?", "jwt_prev_secret").Scan(&prevCount); err != nil {
		t.Fatalf("count jwt_prev_secret: %v", err)
	}
	if prevCount != 0 {
		t.Error("jwt_prev_secret should be removed from system_config")
	}
	var markerCount int
	if err := testDB.QueryRow("SELECT COUNT(*) FROM system_config WHERE key = ?", db.JWTSecretsSeedMarker).Scan(&markerCount); err != nil {
		t.Fatalf("count bootstrap marker: %v", err)
	}
	if markerCount != 1 {
		t.Error("bootstrap marker should remain so the deleted key cannot be re-seeded")
	}
}
