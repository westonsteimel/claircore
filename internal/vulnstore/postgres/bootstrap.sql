--- a unique vulnerability indexed by an updater
CREATE TABLE vuln (
    updater text,
    --- claircore.Vulnerability fields
    id SERIAL PRIMARY KEY,
    --- jsonb to utilize inverted index searches
    vulnerability jsonb,
    --- a tombstone field that will be updated to signify a vulnerability is not stale
    tombstone text
);
--- inverted index to quickly link json field with their documents
CREATE INDEX vuln_inverted_index ON vuln USING gin (vulnerability jsonb_path_ops);

--- UpdateHash
--- a key/value hstore holding the latest update hash for a particular updater
CREATE TABLE updatecursor (
    --- the unique name of the updater. acts a primary key. a single cursor is kept for a particular class
    --- of updater
    updater text PRIMARY KEY,
    --- the last seen hash of the vulnerability database the updater is reponsible for
    hash text,
    --- the last tombstone each vulnerability was created or updated with
    tombstone text
);

