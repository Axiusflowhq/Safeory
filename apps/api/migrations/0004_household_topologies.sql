-- Server-visible authorization topology. Human-readable household/space names,
-- policies, keys, and item content remain in separately encrypted objects.

CREATE TABLE IF NOT EXISTS household_topologies (
    household_id UUID PRIMARY KEY,
    revision BIGINT NOT NULL CHECK (
        revision >= 0 AND revision <= 9007199254740991
    ),
    topology_json TEXT NOT NULL CHECK (
        topology_json <> '' AND octet_length(topology_json) <= 1048576
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
