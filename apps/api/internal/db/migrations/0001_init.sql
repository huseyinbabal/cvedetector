-- Clusters report their inventory through the agent.
CREATE TABLE clusters (
    name          text PRIMARY KEY,
    agent_version text        NOT NULL DEFAULT '',
    first_seen    timestamptz NOT NULL DEFAULT now(),
    last_report   timestamptz NOT NULL DEFAULT now(),
    fingerprint   text        NOT NULL DEFAULT ''
);

-- Current inventory (replaced on every report).
CREATE TABLE images (
    cluster    text    NOT NULL REFERENCES clusters (name) ON DELETE CASCADE,
    ref        text    NOT NULL,
    repository text    NOT NULL,
    tag        text    NOT NULL DEFAULT '',
    digests    text[]  NOT NULL DEFAULT '{}',
    pods       integer NOT NULL DEFAULT 0,
    product    text    NOT NULL DEFAULT '',
    version    text    NOT NULL DEFAULT '',
    status     text    NOT NULL,
    PRIMARY KEY (cluster, ref)
);

CREATE TABLE workloads (
    cluster   text    NOT NULL REFERENCES clusters (name) ON DELETE CASCADE,
    namespace text    NOT NULL,
    kind      text    NOT NULL,
    name      text    NOT NULL,
    pods      integer NOT NULL DEFAULT 0,
    PRIMARY KEY (cluster, namespace, kind, name)
);

CREATE TABLE workload_images (
    cluster   text NOT NULL,
    namespace text NOT NULL,
    kind      text NOT NULL,
    name      text NOT NULL,
    ref       text NOT NULL,
    PRIMARY KEY (cluster, namespace, kind, name, ref),
    FOREIGN KEY (cluster, namespace, kind, name) REFERENCES workloads ON DELETE CASCADE
);
CREATE INDEX workload_images_ref ON workload_images (cluster, ref);

-- Feed, mirrored from the published JSON. revision bumps on every change so
-- API replicas know when to reload their in-memory catalog.
CREATE TABLE feed_state (
    id           integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    url          text        NOT NULL DEFAULT '',
    generated_at timestamptz,
    etag         text        NOT NULL DEFAULT '',
    last_attempt timestamptz,
    last_success timestamptz,
    last_error   text        NOT NULL DEFAULT '',
    revision     bigint      NOT NULL DEFAULT 0
);
INSERT INTO feed_state (id) VALUES (1);

CREATE TABLE products (
    id              text PRIMARY KEY,
    name            text    NOT NULL,
    images          text[]  NOT NULL,
    version_pattern text    NOT NULL DEFAULT '',
    min_segments    integer NOT NULL DEFAULT 0,
    sha256          text    NOT NULL DEFAULT '',
    vuln_count      integer NOT NULL DEFAULT 0
);

CREATE TABLE vulns (
    product     text    NOT NULL REFERENCES products (id) ON DELETE CASCADE,
    id          text    NOT NULL,
    aliases     text[]  NOT NULL DEFAULT '{}',
    summary     text    NOT NULL DEFAULT '',
    severity    text    NOT NULL,
    cvss        double precision NOT NULL DEFAULT 0,
    cvss_vector text    NOT NULL DEFAULT '',
    epss        double precision NOT NULL DEFAULT 0,
    kev         boolean NOT NULL DEFAULT false,
    published   timestamptz,
    refs        text[]  NOT NULL DEFAULT '{}',
    affected    jsonb   NOT NULL,
    PRIMARY KEY (product, id)
);
CREATE INDEX vulns_id ON vulns (id);

-- Findings with history: a row is opened when a vulnerability starts affecting
-- a running image and resolved when it stops (image upgraded or removed, or
-- the feed no longer lists it).
CREATE TABLE findings (
    id          bigserial PRIMARY KEY,
    cluster     text        NOT NULL REFERENCES clusters (name) ON DELETE CASCADE,
    ref         text        NOT NULL,
    product     text        NOT NULL,
    vuln_id     text        NOT NULL,
    fixed_in    text        NOT NULL DEFAULT '',
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,
    resolved_at timestamptz
);
CREATE UNIQUE INDEX findings_open ON findings (cluster, ref, vuln_id) WHERE resolved_at IS NULL;
CREATE INDEX findings_vuln ON findings (vuln_id);
CREATE INDEX findings_history ON findings (cluster, first_seen, resolved_at);
