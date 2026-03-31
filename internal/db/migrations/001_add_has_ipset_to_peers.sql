-- Migration 001: Add has_ipset column to peers table
-- Date: 2026-03-30
-- Purpose: Enable ipset capability detection for group-based firewall rules

-- Add has_ipset column if it doesn't already exist
-- SQLite does not support IF NOT EXISTS for ALTER TABLE ADD COLUMN,
-- so we use a workaround with a temporary table check

SELECT CASE 
    WHEN COUNT(*) = 0 THEN 
        'ALTER TABLE peers ADD COLUMN has_ipset BOOLEAN DEFAULT NULL'
    ELSE 
        'SELECT 1'
END
FROM pragma_table_info('peers')
WHERE name = 'has_ipset';

-- Note: The above SELECT generates the SQL but doesn't execute it.
-- For SQLite, the application code should check pragma_table_info first,
-- then execute the ALTER TABLE only if the column doesn't exist.
-- This is handled by the migrateSchema() function in db.go.

-- Direct migration for reference:
-- ALTER TABLE peers ADD COLUMN has_ipset BOOLEAN DEFAULT NULL;
