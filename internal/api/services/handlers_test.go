package services

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"runic/internal/testutil"
)

// muxVars is a helper to mock gorilla/mux vars
var muxVars = testutil.MuxVars

// =============================================================================
// ListServices Tests
// =============================================================================

func TestListServices_Empty(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(database, nil, nil)
	req := httptest.NewRequest("GET", "/api/v1/services", nil)
	w := httptest.NewRecorder()

	h.ListServices(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var services []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &services); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Empty table - no services seeded in test DB
	if len(services) != 0 {
		t.Errorf("expected 0 services in empty table, got %d", len(services))
	}
}

func TestListServices_Multiple(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Add user services
	database.Exec(`INSERT INTO services (name, ports, source_ports, protocol, description, is_system) VALUES (?, ?, ?, ?, ?, 0)`,
		"http", "80,443", "", "tcp", "HTTP and HTTPS")
	database.Exec(`INSERT INTO services (name, ports, source_ports, protocol, description, is_system) VALUES (?, ?, ?, ?, ?, 0)`,
		"ssh", "22", "", "tcp", "SSH access")

	h := NewHandler(database, nil, nil)
	req := httptest.NewRequest("GET", "/api/v1/services", nil)
	w := httptest.NewRecorder()

	h.ListServices(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var services []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &services); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Should have 2 user services
	if len(services) != 2 {
		t.Errorf("expected 2 services, got %d", len(services))
	}
}

// =============================================================================
// CreateService Tests
// =============================================================================

func TestCreateService_InvalidJSON(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(database, nil, nil)
	req := httptest.NewRequest("POST", "/api/v1/services", bytes.NewBufferString("not valid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.CreateService(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateService_MissingName(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(database, nil, nil)
	body := `{"ports": "80", "protocol": "tcp"}`
	req := httptest.NewRequest("POST", "/api/v1/services", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.CreateService(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateService_InvalidProtocol_ICMP(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(database, nil, nil)
	body := `{"name": "test-icmp", "ports": "", "protocol": "icmp"}`
	req := httptest.NewRequest("POST", "/api/v1/services", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.CreateService(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	if !bytes.Contains(w.Body.Bytes(), []byte("ICMP protocol is reserved for system services")) {
		t.Errorf("expected ICMP error message, got: %s", w.Body.String())
	}
}

func TestCreateService_InvalidProtocol_IGMP(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(database, nil, nil)
	body := `{"name": "test-igmp", "ports": "", "protocol": "igmp"}`
	req := httptest.NewRequest("POST", "/api/v1/services", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.CreateService(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	if !bytes.Contains(w.Body.Bytes(), []byte("IGMP protocol is reserved for system services")) {
		t.Errorf("expected IGMP error message, got: %s", w.Body.String())
	}
}

func TestCreateService_InvalidProtocol_Unknown(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(database, nil, nil)
	body := `{"name": "test-unknown", "ports": "80", "protocol": "unknown"}`
	req := httptest.NewRequest("POST", "/api/v1/services", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.CreateService(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	if !bytes.Contains(w.Body.Bytes(), []byte("invalid protocol")) {
		t.Errorf("expected invalid protocol error message, got: %s", w.Body.String())
	}
}

func TestCreateService_InvalidPortsFormat(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(database, nil, nil)
	body := `{"name": "test-ports", "ports": "invalid!ports", "protocol": "tcp"}`
	req := httptest.NewRequest("POST", "/api/v1/services", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.CreateService(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	if !bytes.Contains(w.Body.Bytes(), []byte("invalid destination ports")) {
		t.Errorf("expected invalid ports error message, got: %s", w.Body.String())
	}
}

func TestCreateService_MissingPorts(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(database, nil, nil)
	body := `{"name": "test-no-ports", "ports": "", "protocol": "tcp"}`
	req := httptest.NewRequest("POST", "/api/v1/services", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.CreateService(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	if !bytes.Contains(w.Body.Bytes(), []byte("at least one port type")) {
		t.Errorf("expected missing ports error message, got: %s", w.Body.String())
	}
}

func TestCreateService_Valid(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(database, nil, nil)
	body := `{"name": "http-service", "ports": "80,443", "protocol": "tcp", "description": "HTTP and HTTPS", "direction_hint": "inbound"}`
	req := httptest.NewRequest("POST", "/api/v1/services", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.CreateService(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var resp map[string]int64
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["id"] == 0 {
		t.Error("expected non-zero id in response")
	}

	// Verify the service was created
	var name string
	err := database.QueryRow("SELECT name FROM services WHERE id = ?", resp["id"]).Scan(&name)
	if err != nil {
		t.Errorf("failed to find created service: %v", err)
	}
	if name != "http-service" {
		t.Errorf("expected name 'http-service', got '%s'", name)
	}
}

// =============================================================================
// GetService Tests
// =============================================================================

func TestGetService_InvalidID(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(database, nil, nil)
	req := httptest.NewRequest("GET", "/api/v1/services/abc", nil)
	req = muxVars(req, map[string]string{"id": "abc"})
	w := httptest.NewRecorder()

	h.GetService(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestGetService_NotFound(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(database, nil, nil)
	req := httptest.NewRequest("GET", "/api/v1/services/99999", nil)
	req = muxVars(req, map[string]string{"id": "99999"})
	w := httptest.NewRecorder()

	h.GetService(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestGetService_Found(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Create a user service
	result, err := database.Exec(`INSERT INTO services (name, ports, source_ports, protocol, description, is_system) VALUES (?, ?, ?, ?, ?, 0)`,
		"test-service", "8080", "", "tcp", "Test service")
	if err != nil {
		t.Fatalf("failed to insert service: %v", err)
	}
	serviceID, _ := result.LastInsertId()

	h := NewHandler(database, nil, nil)
	req := httptest.NewRequest("GET", "/api/v1/services/"+strconv.Itoa(int(serviceID)), nil)
	req = muxVars(req, map[string]string{"id": strconv.Itoa(int(serviceID))})
	w := httptest.NewRecorder()

	h.GetService(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify response contains the service data
	if w.Body.Len() == 0 {
		t.Error("expected non-empty response body")
	}
}

// =============================================================================
// UpdateService Tests
// =============================================================================

func TestUpdateService_InvalidID(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(database, nil, nil)
	req := httptest.NewRequest("PUT", "/api/v1/services/abc", nil)
	req = muxVars(req, map[string]string{"id": "abc"})
	w := httptest.NewRecorder()

	h.UpdateService(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestUpdateService_NotFound(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(database, nil, nil)
	body := `{"name": "updated", "ports": "80"}`
	req := httptest.NewRequest("PUT", "/api/v1/services/99999", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = muxVars(req, map[string]string{"id": "99999"})
	w := httptest.NewRecorder()

	h.UpdateService(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestUpdateService_SystemService_Forbidden(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// First insert a system service (is_system = 1)
	database.Exec(`INSERT INTO services (name, ports, protocol, is_system) VALUES (?, ?, ?, 1)`,
		"ICMP", "", "icmp")

	// Get the service ID
	var serviceID int
	err := database.QueryRow("SELECT id FROM services WHERE name = 'ICMP'").Scan(&serviceID)
	if err != nil {
		t.Fatalf("failed to find service: %v", err)
	}

	h := NewHandler(database, nil, nil)
	body := `{"name": "updated-icmp", "ports": "80"}`
	req := httptest.NewRequest("PUT", "/api/v1/services/"+strconv.Itoa(serviceID), bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = muxVars(req, map[string]string{"id": strconv.Itoa(serviceID)})
	w := httptest.NewRecorder()

	h.UpdateService(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d: %s", http.StatusForbidden, w.Code, w.Body.String())
	}

	if !bytes.Contains(w.Body.Bytes(), []byte("Cannot edit system service")) {
		t.Errorf("expected system service error message, got: %s", w.Body.String())
	}
}

func TestUpdateService_InvalidJSON(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Create a user service
	result, _ := database.Exec(`INSERT INTO services (name, ports, protocol, is_system) VALUES (?, ?, ?, 0)`,
		"user-service", "8080", "tcp")
	serviceID, _ := result.LastInsertId()

	h := NewHandler(database, nil, nil)
	req := httptest.NewRequest("PUT", "/api/v1/services/"+strconv.Itoa(int(serviceID)), bytes.NewBufferString("not valid json"))
	req.Header.Set("Content-Type", "application/json")
	req = muxVars(req, map[string]string{"id": strconv.Itoa(int(serviceID))})
	w := httptest.NewRecorder()

	h.UpdateService(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestUpdateService_InvalidProtocol(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Create a user service
	result, _ := database.Exec(`INSERT INTO services (name, ports, protocol, is_system) VALUES (?, ?, ?, 0)`,
		"user-service", "8080", "tcp")
	serviceID, _ := result.LastInsertId()

	h := NewHandler(database, nil, nil)
	body := `{"name": "updated", "ports": "80", "protocol": "icmp"}`
	req := httptest.NewRequest("PUT", "/api/v1/services/"+strconv.Itoa(int(serviceID)), bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = muxVars(req, map[string]string{"id": strconv.Itoa(int(serviceID))})
	w := httptest.NewRecorder()

	h.UpdateService(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	if !bytes.Contains(w.Body.Bytes(), []byte("ICMP protocol is reserved for system services")) {
		t.Errorf("expected ICMP error message, got: %s", w.Body.String())
	}
}

func TestUpdateService_Valid(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Create a user service
	result, _ := database.Exec(`INSERT INTO services (name, ports, source_ports, protocol, description, is_system) VALUES (?, ?, ?, ?, ?, 0)`,
		"old-name", "8080", "", "tcp", "old description")
	serviceID, _ := result.LastInsertId()

	h := NewHandler(database, nil, nil)
	body := `{"name": "new-name", "ports": "9090", "source_ports": "1000,2000,3000", "protocol": "udp", "description": "new description", "direction_hint": "outbound"}`
	req := httptest.NewRequest("PUT", "/api/v1/services/"+strconv.Itoa(int(serviceID)), bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = muxVars(req, map[string]string{"id": strconv.Itoa(int(serviceID))})
	w := httptest.NewRecorder()

	h.UpdateService(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["status"] != "updated" {
		t.Errorf("expected status 'updated', got '%s'", resp["status"])
	}

	// Verify the service was updated
	var name, ports, protocol string
	err := database.QueryRow("SELECT name, ports, protocol FROM services WHERE id = ?", serviceID).Scan(&name, &ports, &protocol)
	if err != nil {
		t.Errorf("failed to find updated service: %v", err)
	}
	if name != "new-name" {
		t.Errorf("expected name 'new-name', got '%s'", name)
	}
	if ports != "9090" {
		t.Errorf("expected ports '9090', got '%s'", ports)
	}
	if protocol != "udp" {
		t.Errorf("expected protocol 'udp', got '%s'", protocol)
	}
}

// =============================================================================
// DeleteService Tests
// =============================================================================

func TestDeleteService_InvalidID(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(database, nil, nil)
	req := httptest.NewRequest("DELETE", "/api/v1/services/abc", nil)
	req = muxVars(req, map[string]string{"id": "abc"})
	w := httptest.NewRecorder()

	h.DeleteService(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDeleteService_NotFound(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	h := NewHandler(database, nil, nil)
	req := httptest.NewRequest("DELETE", "/api/v1/services/99999", nil)
	req = muxVars(req, map[string]string{"id": "99999"})
	w := httptest.NewRecorder()

	h.DeleteService(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestDeleteService_SystemService_Forbidden(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// First insert a system service (is_system = 1)
	database.Exec(`INSERT INTO services (name, ports, protocol, is_system) VALUES (?, ?, ?, 1)`,
		"ICMP", "", "icmp")

	// Get the service ID
	var serviceID int
	err := database.QueryRow("SELECT id FROM services WHERE name = 'ICMP'").Scan(&serviceID)
	if err != nil {
		t.Fatalf("failed to find service: %v", err)
	}

	h := NewHandler(database, nil, nil)
	req := httptest.NewRequest("DELETE", "/api/v1/services/"+strconv.Itoa(serviceID), nil)
	req = muxVars(req, map[string]string{"id": strconv.Itoa(serviceID)})
	w := httptest.NewRecorder()

	h.DeleteService(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d: %s", http.StatusForbidden, w.Code, w.Body.String())
	}

	if !bytes.Contains(w.Body.Bytes(), []byte("Cannot delete system service")) {
		t.Errorf("expected system service error message, got: %s", w.Body.String())
	}
}

func TestDeleteService_Valid(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Create a user service
	result, _ := database.Exec(`INSERT INTO services (name, ports, protocol, is_system) VALUES (?, ?, ?, 0)`, "to-delete", "8080", "tcp")
	serviceID, _ := result.LastInsertId()

	h := NewHandler(database, nil, nil)
	req := httptest.NewRequest("DELETE", "/api/v1/services/"+strconv.Itoa(int(serviceID)), nil)
	req = muxVars(req, map[string]string{"id": strconv.Itoa(int(serviceID))})
	w := httptest.NewRecorder()

	h.DeleteService(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, w.Code)
	}

	// Verify the service was deleted
	var count int
	err := database.QueryRow("SELECT COUNT(*) FROM services WHERE id = ?", serviceID).Scan(&count)
	if err != nil {
		t.Errorf("failed to query services: %v", err)
	}
	if count != 0 {
		t.Errorf("expected service to be deleted, but it still exists")
	}
}

func TestDeleteService_InUseByPolicy(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Create a user service
	serviceResult, err := database.Exec(`INSERT INTO services (name, ports, protocol, is_system) VALUES (?, ?, ?, 0)`, "web-service", "80,443", "tcp")
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}
	serviceID, _ := serviceResult.LastInsertId()

	// Create a source group for policies
	groupResult, err := database.Exec(`INSERT INTO groups (name, description, is_system) VALUES (?, ?, 0)`, "web-servers", "Web server group")
	if err != nil {
		t.Fatalf("failed to create group: %v", err)
	}
	groupID, _ := groupResult.LastInsertId()

	// Create multiple policies that use this service
	policyResult1, err := database.Exec(`
		INSERT INTO policies (name, description, source_id, source_type, service_id, target_id, target_type, action, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"allow-https", "Allow HTTPS traffic", groupID, "group", serviceID, 1, "special", "ACCEPT", 1)
	if err != nil {
		t.Fatalf("failed to create policy 1: %v", err)
	}
	policyID1, _ := policyResult1.LastInsertId()

	policyResult2, err := database.Exec(`
		INSERT INTO policies (name, description, source_id, source_type, service_id, target_id, target_type, action, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"allow-http", "Allow HTTP traffic", groupID, "group", serviceID, 2, "special", "ACCEPT", 1)
	if err != nil {
		t.Fatalf("failed to create policy 2: %v", err)
	}
	policyID2, _ := policyResult2.LastInsertId()

	// Try to delete the service
	h := NewHandler(database, nil, nil)
	req := httptest.NewRequest("DELETE", "/api/v1/services/"+strconv.Itoa(int(serviceID)), nil)
	req = muxVars(req, map[string]string{"id": strconv.Itoa(int(serviceID))})
	w := httptest.NewRecorder()

	h.DeleteService(w, req)

	// Should return 409 Conflict
	if w.Code != http.StatusConflict {
		t.Errorf("expected status %d, got %d: %s", http.StatusConflict, w.Code, w.Body.String())
	}

	// Parse response to verify it contains the list of policies
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Verify error message
	if errMsg, ok := resp["error"].(string); !ok || errMsg == "" {
		t.Error("expected error message in response")
	}

	// Verify policies list
	policiesRaw, ok := resp["policies"]
	if !ok {
		t.Fatal("expected policies field in response")
	}

	policies, ok := policiesRaw.([]interface{})
	if !ok {
		t.Fatal("expected policies to be an array")
	}

	if len(policies) != 2 {
		t.Errorf("expected 2 policies in response, got %d", len(policies))
	}

	// Verify policy IDs and names are in the response
	policyMap := make(map[int]string)
	for _, p := range policies {
		policy, ok := p.(map[string]interface{})
		if !ok {
			t.Fatal("expected policy to be an object")
		}

		idFloat, ok := policy["id"].(float64)
		if !ok {
			t.Fatal("expected policy id to be a number")
		}
		id := int(idFloat)

		name, ok := policy["name"].(string)
		if !ok {
			t.Fatal("expected policy name to be a string")
		}
		policyMap[id] = name
	}

	// Check that both policies are present
	if _, ok := policyMap[int(policyID1)]; !ok {
		t.Errorf("policy %d not found in response", policyID1)
	}
	if _, ok := policyMap[int(policyID2)]; !ok {
		t.Errorf("policy %d not found in response", policyID2)
	}

	// Verify the service was NOT deleted
	var count int
	err = database.QueryRow("SELECT COUNT(*) FROM services WHERE id = ?", serviceID).Scan(&count)
	if err != nil {
		t.Errorf("failed to query services: %v", err)
	}
	if count != 1 {
		t.Errorf("expected service to still exist, but count = %d", count)
	}
}

func TestDeleteService_NotInUse_Success(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Create a user service
	serviceResult, err := database.Exec(`INSERT INTO services (name, ports, protocol, is_system) VALUES (?, ?, ?, 0)`, "standalone-service", "9000", "tcp")
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}
	serviceID, _ := serviceResult.LastInsertId()

	// Create a different service that IS in use (to verify we're not blocking all deletions)
	usedServiceResult, err := database.Exec(`INSERT INTO services (name, ports, protocol, is_system) VALUES (?, ?, ?, 0)`, "used-service", "8080", "tcp")
	if err != nil {
		t.Fatalf("failed to create used service: %v", err)
	}
	usedServiceID, _ := usedServiceResult.LastInsertId()

	// Create a source group
	groupResult, err := database.Exec(`INSERT INTO groups (name, description, is_system) VALUES (?, ?, 0)`, "test-group", "Test group")
	if err != nil {
		t.Fatalf("failed to create group: %v", err)
	}
	groupID, _ := groupResult.LastInsertId()

	// Create a policy that uses the usedService (not the standalone-service)
	_, err = database.Exec(`
		INSERT INTO policies (name, description, source_id, source_type, service_id, target_id, target_type, action, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"test-policy", "Test policy", groupID, "group", usedServiceID, 1, "special", "ACCEPT", 1)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	// Delete the standalone service (not in use)
	h := NewHandler(database, nil, nil)
	req := httptest.NewRequest("DELETE", "/api/v1/services/"+strconv.Itoa(int(serviceID)), nil)
	req = muxVars(req, map[string]string{"id": strconv.Itoa(int(serviceID))})
	w := httptest.NewRecorder()

	h.DeleteService(w, req)

	// Should return 204 No Content
	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d: %s", http.StatusNoContent, w.Code, w.Body.String())
	}

	// Verify the service was deleted
	var count int
	err = database.QueryRow("SELECT COUNT(*) FROM services WHERE id = ?", serviceID).Scan(&count)
	if err != nil {
		t.Errorf("failed to query services: %v", err)
	}
	if count != 0 {
		t.Errorf("expected service to be deleted, but it still exists")
	}

	// Verify the used service still exists (not affected)
	err = database.QueryRow("SELECT COUNT(*) FROM services WHERE id = ?", usedServiceID).Scan(&count)
	if err != nil {
		t.Errorf("failed to query services: %v", err)
	}
	if count != 1 {
		t.Errorf("expected used service to still exist, but count = %d", count)
	}
}
