CREATE DATABASE IF NOT EXISTS aegisgraph;

CREATE TABLE IF NOT EXISTS aegisgraph.security_events
(
    event_id UUID,
    observed_at DateTime64(9, 'UTC'),
    received_at DateTime64(9, 'UTC'),
    host_id LowCardinality(String),
    workload_id LowCardinality(String),
    event_type LowCardinality(String),
    process_id String,
    parent_process_id String,
    executable String,
    object_type LowCardinality(String),
    object_value String,
    event_json String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(observed_at)
ORDER BY (host_id, workload_id, observed_at, event_id)
TTL observed_at + INTERVAL 90 DAY;
