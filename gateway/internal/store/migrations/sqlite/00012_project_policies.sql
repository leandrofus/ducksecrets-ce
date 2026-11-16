-- +goose Up
CREATE TABLE project_policies (
    id               TEXT PRIMARY KEY,
    project_id       TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    subject_type     TEXT NOT NULL CHECK (subject_type IN ('user', 'role')),
    subject_id       TEXT NOT NULL,
    environment_slug TEXT NOT NULL DEFAULT '*',
    can_read         BOOLEAN NOT NULL DEFAULT 1,
    can_write        BOOLEAN NOT NULL DEFAULT 0,
    can_admin        BOOLEAN NOT NULL DEFAULT 0,
    starts_at        DATETIME,
    expires_at       DATETIME,
    description      TEXT NOT NULL DEFAULT '',
    created_by       TEXT,
    created_at       DATETIME NOT NULL,
    UNIQUE(project_id, subject_type, subject_id, environment_slug)
);

CREATE INDEX project_policies_proj_idx ON project_policies (project_id);
CREATE INDEX project_policies_subj_idx ON project_policies (subject_type, subject_id);

-- +goose Down
DROP TABLE IF EXISTS project_policies;
