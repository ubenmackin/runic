#!/bin/bash
# Manual major version bump for agent
# Usage: ./scripts/bump-agent-major.sh [major-version]
# - If no argument provided, increments current major version by 1
# - If argument provided, sets major version to that number

set -e

VERSION_FILE=".agent-version"

if [ ! -f "$VERSION_FILE" ]; then
    echo "Error: $VERSION_FILE not found"
    exit 1
fi

# Get current version
CURRENT=$(cat "$VERSION_FILE")
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"

# Determine new major version
if [ -n "$1" ]; then
    NEW_MAJOR="$1"
else
    NEW_MAJOR=$((MAJOR + 1))
fi

# Create new version (reset minor and patch)
NEW_VERSION="$NEW_MAJOR.0.0"

# Update version file
echo "$NEW_VERSION" > "$VERSION_FILE"

echo "Major version bump: $CURRENT -> $NEW_VERSION"
echo ""
echo "Next steps:"
echo " 1. Review the change: git diff .agent-version"
echo " 2. Commit: git add .agent-version && git commit -m 'chore: bump agent major version to $NEW_VERSION'"
echo " 3. Push: git push"
