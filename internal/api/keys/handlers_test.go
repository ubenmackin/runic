package keys

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gorilla/mux"
)

func setupTestEnv(t *testing.T) (string, func()) {
	t.Helper()

	// Create temp directory for .env file
	tempDir := t.TempDir()
	envPath := filepath.Join(tempDir, ".env")

	// Override the env path
	original := os.Getenv("RUNIC_ENV_PATH")
	os.Setenv("RUNIC_ENV_PATH", envPath)

	cleanup := func() {
		if original != "" {
			os.Setenv("RUNIC_ENV_PATH", original)
		} else {
			os.Unsetenv("RUNIC_ENV_PATH")
		}
	}

	return envPath, cleanup
}

func setupRouter() *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/api/v1/setup-keys", ListKeys).Methods("GET")
	router.HandleFunc("/api/v1/setup-keys/{type}", CreateKey).Methods("POST")
	router.HandleFunc("/api/v1/setup-keys/{type}", DeleteKey).Methods("DELETE")
	return router
}

func TestListKeys_Empty(t *testing.T) {
	_, cleanup := setupTestEnv(t)
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
	envPath, cleanup := setupTestEnv(t)
	defer cleanup()

	router := setupRouter()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup-keys/jwt-secret", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("CreateKey() status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Verify .env file was created
	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read .env file: %v", err)
	}

	content := string(data)
	if len(content) == 0 {
		t.Error(".env file is empty after creating key")
	}
}

func TestCreateKey_InvalidType(t *testing.T) {
	_, cleanup := setupTestEnv(t)
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
	envPath, cleanup := setupTestEnv(t)
	defer cleanup()

	router := setupRouter()

	// Create a key first
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/setup-keys/jwt-secret", nil)
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusOK {
		t.Fatalf("CreateKey() failed: status = %d", createRec.Code)
	}

	// Delete the key
	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/setup-keys/jwt-secret", nil)
	deleteRec := httptest.NewRecorder()
	router.ServeHTTP(deleteRec, deleteReq)

	if deleteRec.Code != http.StatusOK {
		t.Errorf("DeleteKey() status = %d, want %d", deleteRec.Code, http.StatusOK)
	}

	// Verify key was removed from .env
	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read .env file: %v", err)
	}

	content := string(data)
	if len(content) > 0 {
		t.Error(".env file should be empty after deleting key")
	}
}

func TestDeleteKey_NonExistent(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()

	router := setupRouter()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/setup-keys/jwt-secret", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("DeleteKey() status = %d, want %d", rec.Code, http.StatusOK)
	}
}
