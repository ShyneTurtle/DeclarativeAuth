-- +goose Up
-- Authenticator-app (TOTP) enrolment. secret_enc is the active, confirmed
-- secret; pending_secret_enc holds a secret shown to the user but not yet
-- confirmed with a valid code, so re-enrolling never invalidates the working
-- secret until the new one is proven. Both are AES-GCM sealed.
-- last_step is the last accepted time-step, for single-use enforcement.
CREATE TABLE user_totp (
    username            TEXT PRIMARY KEY,
    secret_enc          BYTEA,
    pending_secret_enc  BYTEA,
    last_step           BIGINT NOT NULL DEFAULT 0,
    confirmed_at        TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A login challenge now has a stage and may be created without sending an
-- email: users with an authenticator app default to it and can ask for an
-- emailed code instead. stage 'enroll' is a challenge issued only AFTER the
-- login's MFA step passed, entitling its holder to enrol an authenticator
-- app (and then finish signing in) -- it must never be usable for 'verify'.
ALTER TABLE mfa_email_challenges
    ADD COLUMN stage TEXT NOT NULL DEFAULT 'verify',
    ADD COLUMN email_sent BOOLEAN NOT NULL DEFAULT true;

-- +goose Down
ALTER TABLE mfa_email_challenges DROP COLUMN email_sent, DROP COLUMN stage;
DROP TABLE user_totp;
