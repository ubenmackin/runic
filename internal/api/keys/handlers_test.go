package keys

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"runic/internal/db"
)

func setupTestDB(t *testing.T) func() {
	t.Helper()

	// Create in-memory SQLite database
	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}

	// Create system_config table
	_, err = sqlDB.Exec(`
		CREATE TABLE system_config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		t.Fatalf("failed to create system_config table: %v", err)
	}

	// Save original DB and replace with test DB
	originalDB := db.DB
	db.DB = db.New(sqlDB)

	return func() {
		db.DB = originalDB
		sqlDB.Close()
	}
}

func setupRouter() *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/api/v1/setup-keys", ListKeys).Methods("GET")
	router.HandleFunc("/api/v1/setup-keys/{type}", CreateKey).Methods("POST")
	router.HandleFunc("/api/v1/setup-keys/{type}", DeleteKey).Methods("DELETE")
	return router
}

func TestListKeys_Empty(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	router := setupRouter()
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
	cleanup := setupTestDB(t)
	defer cleanup()

	router := setupRouter()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup-keys/jwt-secret", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("CreateKey() status = %d, want %d", rec.Code, http.StatusOK)
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
	err := db.DB.QueryRow("SELECT value FROM system_config WHERE key = ?", "jwt_secret").Scan(&value)
	if err != nil {
		t.Fatalf("jwt_secret not found in system_config: %v", err)
	}
	if len(value) == 0 {
		t.Error("jwt_secret value is empty")
	}
}

func TestCreateKey_InvalidType(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	router := setupRouter()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup-keys/invalid-type", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("CreateKey() status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestDeleteKey_Success(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	router := setupRouter()

	// Create a key first
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/setup-keys/jwt-secret", nil)
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusOK {
		t.Fatalf("CreateKey() failed: status = %d", createRec.Code)
	}

	// Verify key exists
	var value string
	err := db.DB.QueryRow("SELECT value FROM system_config WHERE key = ?", "jwt_secret").Scan(&value)
	if err != nil {
		t.Fatalf("jwt_secret not found in system_config after create: %v", err)
	}

	// Delete the key
	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/setup-keys/jwt-secret", nil)
	deleteRec := httptest.NewRecorder()
	router.ServeHTTP(deleteRec, deleteReq)

	if deleteRec.Code != http.StatusOK {
		t.Errorf("DeleteKey() status = %d, want %d", deleteRec.Code, http.StatusOK)
	}

	// Verify key was removed from system_config
	err = db.DB.QueryRow("SELECT value FROM system_config WHERE key = ?", "jwt_secret").Scan(&value)
	if err != sql.ErrNoRows {
		t.Error("jwt_secret should have been removed from system_config")
	}
}

func TestDeleteKey_NonExistent(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	router := setupRouter()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/setup-keys/jwt-secret", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("DeleteKey() status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestListKeys_AfterCreate(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	router := setupRouter()

	// Create jwt-secret
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/setup-keys/jwt-secret", nil)
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusOK {
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
