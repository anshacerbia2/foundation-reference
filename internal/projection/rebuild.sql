-- The rebuild path, applied only when asked for: `foundation-reference-migrate -rebuild`.
--
-- A projection's recovery is rebuild-from-snapshot rather than repair, so dropping it is a legitimate
-- operation — but it is an operation somebody chooses, never a side effect of a migration run. An
-- unconditional DROP in schema.sql would delete the projection on every deploy, and the consumer
-- would then refuse every projection-backed operation until it had bootstrapped again. That is
-- correct behaviour for a consumer with no positive authority, and a catastrophic default.
--
-- After this runs, the consumer holds nothing and its watermark carries no snapshot mark, so every
-- projection-backed enforcement check refuses until:
--
--     snapshot at mark M  ->  bootstrap  ->  catch-up events after M
--
-- which is the whole point of keeping the two files apart: the state after a rebuild is honest about
-- what it knows, rather than an empty table that reads as "nothing is revoked".

DROP TABLE IF EXISTS projection.membership;
DROP TABLE IF EXISTS projection.watermark;
