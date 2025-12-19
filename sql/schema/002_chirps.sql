-- +goose Up
CREATE TABLE chirps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    body VARCHAR(140) NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_chirps_user_id ON chirps(user_id);
CREATE INDEX idx_chirps_created_at ON chirps(created_at);

-- +goose Down
DROP TABLE IF EXISTS chirps;