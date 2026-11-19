-- EPSS scores ship in their own feed file (v1/epss.json) because they change
-- daily; remember which version is applied.
ALTER TABLE feed_state ADD COLUMN epss_sha text NOT NULL DEFAULT '';
