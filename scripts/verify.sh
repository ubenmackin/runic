#!/bin/bash

# Define colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "Starting full project verification..."

cd ..

# 1. Cleanup
make clean > /dev/null 2>&1

# 2. Go Lint
GO_LINT_COUNT=$(golangci-lint run ./... 2>&1 | grep -c ":" | tail -n 1 | xargs)
echo -e "Go Lint: $GO_LINT_COUNT issues"

# 3. Go Test
make test-go > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "Go Test: ${GREEN}PASS${NC}"
else
    echo -e "Go Test: ${RED}FAILED${NC}"
fi

# 4. React Lint
# Captures the number of problems reported by ESLint/NPM
REACT_LINT_COUNT=$(cd web && npm run lint 2>&1 | grep -oE "[0-9]+ problems" | awk '{print $1}' | awk '{s+=$1} END {print s+0}')
echo -e "React Lint: $REACT_LINT_COUNT issues"

# 5. React Test
make test-web > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "React Test: ${GREEN}PASS${NC}"
else
    echo -e "React Test: ${RED}FAILED${NC}"
fi

# 6. Web Build
make web-build > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "Web Build: ${GREEN}PASS${NC}"
else
    echo -e "Web Build: ${RED}FAILED${NC}"
fi

# 7. Go Build
make build > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "Server Build: ${GREEN}PASS${NC}"
else
    echo -e "Server Build: ${RED}FAILED${NC}"
fi

# 7. Go Build
make agents > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "Agent Build: ${GREEN}PASS${NC}"
else
    echo -e "Agent Build: ${RED}FAILED${NC}"
fi
