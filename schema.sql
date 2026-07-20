-- Drop tables if they exist to ensure a clean slate
DROP TABLE IF EXISTS state_balances;
DROP TABLE IF EXISTS utvn_blocks;

-- Create the immutable ledger table
CREATE TABLE utvn_blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    payload TEXT NOT NULL,
    signature TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    current_hash TEXT NOT NULL
);

-- Create an index on the ID for high-speed sequential audits
CREATE INDEX IF NOT EXISTS idx_block_id ON utvn_blocks(id);

-- Create the deterministic state balance table for automated mutations
CREATE TABLE state_balances (
    recipient_identifier TEXT PRIMARY KEY,
    asset_class TEXT NOT NULL,
    total_allocated_units REAL NOT NULL DEFAULT 0,
    last_updated TEXT NOT NULL
);

-- Create an index on asset_class for fast queries by allocation type
CREATE INDEX IF NOT EXISTS idx_state_asset_class ON state_balances(asset_class);
