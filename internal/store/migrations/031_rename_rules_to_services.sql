-- Rename rules_json to services_json in broker_configs and proposals tables.
ALTER TABLE broker_configs RENAME COLUMN rules_json TO services_json;
ALTER TABLE proposals RENAME COLUMN rules_json TO services_json;
