package keys

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"

	"runic/internal/testutil"
)

func setupRouter(handler *Handler) *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/api/v1/setup-keys", handler.ListKeys).Methods("GET")
	router.HandleFunc("/api/v1/setup-keys/{type}", handler.CreateKey).Methods("POST")
	router.HandleFunc("/api/v1/setup-keys/{type}", handler.DeleteKey).Methods("DELETE")
	return router
}

func TestListKeys_Empty(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	handler := NewHandler(db)
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

	handler := NewHandler(testDB)
	router := setupRouter(handler)
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
	err := testDB.QueryRow("SELECT value FROM system_config WHERE key = ?", "jwt_secret").Scan(&value)
	if err != nil {
		t.Fatalf("jwt_secret not found in system_config: %v", err)
	}
	if len(value) == 0 {
		t.Error("jwt_secret value is empty")
	}
}

func TestCreateKey_InvalidType(t *testing.T) {
	testDB, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	handler := NewHandler(testDB)
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

	handler := NewHandler(testDB)
	router := setupRouter(handler)

	// Create a key first
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/setup-keys/jwt-secret", nil)
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusOK {
		t.Fatalf("CreateKey() failed: status = %d", createRec.Code)
	}

	// Verify key exists
	var value string
	err := testDB.QueryRow("SELECT value FROM system_config WHERE key = ?", "jwt_secret").Scan(&value)
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
	err = testDB.QueryRow("SELECT value FROM system_config WHERE key = ?", "jwt_secret").Scan(&value)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Error("jwt_secret should have been removed from system_config")
	}
}

func TestDeleteKey_NonExistent(t *testing.T) {
	testDB, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	handler := NewHandler(testDB)
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

	handler := NewHandler(testDB)
	router := setupRouter(handler)

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
