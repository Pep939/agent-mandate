-- Least-privilege role DDL for the Mandate ledger (ADR-0014).
--
-- Run ONCE per database by a deployer with elevated privileges:
--     psql "$MANDATE_DB_URL" -f migrations/sql/roles.sql
-- Deliberately outside the Alembic chain: roles are database-level objects,
-- not part of the schema Alembic manages.
--
-- Postgres grants are per-database, so this must run in the same database
-- the app uses. The password is a local-dev default — replace it for any
-- deployment that is not loopback-only, and keep the real value out of
-- source control (invariant 12).

CREATE ROLE mandate_app LOGIN PASSWORD 'mandate_app_dev_password_change_me';

-- Do not rely on the cluster default for `public`: some deployments revoke
-- USAGE from PUBLIC (Postgres >= 15 removed CREATE; USAGE can go with it).
GRANT USAGE ON SCHEMA public TO mandate_app;

-- Read + append on every governed table (deal_links per the ADR-0014
-- addendum: the app writes the deal → mandate registry on registration).
GRANT SELECT, INSERT, REFERENCES ON
    events, revocations, authority_records, deal_links, deals, approvals,
    seen_nonces, seen_requests, idempotency, seen_commands, message_dedup
TO mandate_app;

-- The two current-state projections are the only rows the app rewrites
-- (every deal transition; an approval pending -> granted/denied). No
-- DELETE, no TRUNCATE, no DDL anywhere — and the append-only triggers in
-- migration 0004 stop even this role from touching the rest.
GRANT UPDATE ON deals, approvals TO mandate_app;
