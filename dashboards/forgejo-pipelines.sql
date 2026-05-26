-- Views that expose the Forgejo pipeline data collected by kxn as flat,
-- typed columns for the dashboards/forgejo-pipelines.json Grafana panels.
--
-- kxn save writes every gathered resource into the JSONB `content` column
-- of the `resources` table. To keep the dashboard SQL readable and
-- allow Postgres to plan indexes properly, we surface three views — one
-- per Forgejo resource type — over that table. Re-running this script
-- is idempotent: it `CREATE OR REPLACE`s the views and only adds the
-- indexes if they do not exist yet.
--
-- Apply once against the kxn Postgres database after deploying the
-- Forgejo provider:
--
--   psql "$KXN_DATABASE_URL" -f dashboards/forgejo-pipelines.sql

CREATE OR REPLACE VIEW pipeline_runs AS
SELECT
    (content->>'run_id')::bigint                            AS run_id,
    content->>'repo'                                        AS repo,
    content->>'owner'                                       AS owner,
    content->>'repo_name'                                   AS repo_name,
    content->>'workflow_name'                               AS workflow_name,
    (content->>'workflow_id')::bigint                       AS workflow_id,
    (content->>'run_number')::int                           AS run_number,
    content->>'event'                                       AS event,
    content->>'status'                                      AS status,
    content->>'conclusion'                                  AS conclusion,
    content->>'head_branch'                                 AS head_branch,
    content->>'head_sha'                                    AS head_sha,
    content->>'actor'                                       AS actor,
    content->>'triggering_actor'                            AS triggering_actor,
    (content->>'created_at')::timestamptz                   AS created_at,
    (content->>'started_at')::timestamptz                   AS started_at,
    (content->>'updated_at')::timestamptz                   AS updated_at,
    content->>'html_url'                                    AS html_url,
    created_at                                              AS collected_at
FROM resources
WHERE content ? 'run_id'
  AND content ? 'workflow_name'
  AND NOT (content ? 'log_text')
  AND NOT (content ? 'job_id' AND NOT content ? 'workflow_name');

CREATE OR REPLACE VIEW pipeline_jobs AS
SELECT
    (content->>'job_id')::bigint                            AS job_id,
    (content->>'run_id')::bigint                            AS run_id,
    content->>'repo'                                        AS repo,
    content->>'name'                                        AS name,
    content->>'status'                                      AS status,
    content->>'conclusion'                                  AS conclusion,
    (content->>'started_at')::timestamptz                   AS started_at,
    (content->>'completed_at')::timestamptz                 AS completed_at,
    content->>'runner_name'                                 AS runner_name,
    content->>'runner_group_name'                           AS runner_group_name,
    content->'labels'                                       AS labels,
    content->>'html_url'                                    AS html_url,
    content->'steps'                                        AS steps,
    created_at                                              AS collected_at
FROM resources
WHERE content ? 'job_id'
  AND content ? 'run_id'
  AND content ? 'name'
  AND NOT (content ? 'log_text');

CREATE OR REPLACE VIEW pipeline_logs AS
SELECT
    (content->>'job_id')::bigint                            AS job_id,
    (content->>'run_id')::bigint                            AS run_id,
    content->>'repo'                                        AS repo,
    content->>'log_text'                                    AS log_text,
    (content->>'log_size_bytes')::bigint                    AS log_size_bytes,
    created_at                                              AS collected_at
FROM resources
WHERE content ? 'log_text'
  AND content ? 'job_id';

-- Targeted indexes on the JSONB column to keep dashboard queries fast on
-- a busy CI history. The dashboard always filters by repo / time window.
CREATE INDEX IF NOT EXISTS idx_resources_pipeline_run_id
    ON resources ((content->>'run_id'))
    WHERE content ? 'run_id';

CREATE INDEX IF NOT EXISTS idx_resources_pipeline_job_id
    ON resources ((content->>'job_id'))
    WHERE content ? 'job_id';

CREATE INDEX IF NOT EXISTS idx_resources_pipeline_repo
    ON resources ((content->>'repo'))
    WHERE content ? 'repo' AND (content ? 'run_id' OR content ? 'job_id');
