# Phase 1 API Handlers - Review Checklist

## Coverage Requirements
- All handler packages must achieve **80% minimum** test coverage
- Critical packages (<50%) must be prioritized for immediate fixes

## DRY Compliance
- All test helper functions should use `testutil` package
- No duplicate helper functions should exist (e.g., `setupTestDBWithX`)
- Direct use of `testutil.SetupTestDB()`, `testutil.SetupTestDBWithSecret()`, `testutil.SetupTestDBWithTestData()` preferred

## Testutil Usage Guidelines
1. **Database Setup:**
   - Use `testutil.SetupTestDB(t)` for basic test database
   - Use `testutil.SetupTestDBWithSecret(t)` when JWT/agent auth is needed
   - Use `testutil.SetupTestDBWithTestData(t)` for pre-populated test data

2. **HTTP Testing:**
   - Use `testutil.MuxVars(req, vars)` to set URL variables for gorilla/mux
   - Use `httptest.NewRecorder()` for response capture
   - Use `httptest.NewRequest()` for request creation

3. **Shared Helpers:**
   - Check `testutil/` package before creating local helpers
   - Contribute reusable helpers to `testutil/` when appropriate

## Reviewer Sign-off Requirements
Before approving any PR, verify:

### 1. Coverage Check
- [ ] Run `go test ./internal/api/<package>/... -cover`
- [ ] Verify coverage meets 80% threshold
- [ ] Document any gaps and plan to address

### 2. DRY Check
- [ ] Search for duplicate helper patterns
- [ ] Ensure testutil is properly utilized
- [ ] No redundant wrapper functions

### 3. Test Quality
- [ ] Tests actually invoke handlers (not just raw SQL)
- [ ] Error paths are covered
- [ ] Edge cases included
- [ ] Tests pass reliably

### 4. Code Review
- [ ] No obvious bugs in test logic
- [ ] Proper cleanup (defer cleanup())
- [ ] No race conditions in concurrent tests

## Approval Comment Template
```
REVIEW CHECKLIST:
- [ ] Coverage: XX% (target: 80%)
- [ ] DRY: Compliant
- [ ] Tests: Quality verified
- [ ] Status: APPROVED
```

## Related Files
- Testutil package: `internal/testutil/`
- Phase 1 handlers: `internal/api/*/handlers_test.go`
- Coverage report: Run `go test ./internal/api/... -cover`
