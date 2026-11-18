-- Test-only data for the database secrets engine round trip.
CREATE TABLE IF NOT EXISTS sdk_probe (id integer PRIMARY KEY, label text NOT NULL);
INSERT INTO sdk_probe (id, label) VALUES (1, 'grow-sdk-probe') ON CONFLICT (id) DO NOTHING;
