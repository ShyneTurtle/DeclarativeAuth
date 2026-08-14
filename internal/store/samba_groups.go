package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SambaGroupStore assigns and persists the RID each declarative group needs
// to be rendered as a sambaGroupMapping entry -- see samba_group_rids in
// migrations. Declarative groups themselves are config, not a Postgres row;
// this table only tracks the one piece of state (the RID) that has to stay
// stable across reloads/restarts once a Windows client has resolved it into
// an ACL.
type SambaGroupStore struct {
	Pool *pgxpool.Pool
}

// EnsureRIDs returns the current RID for every name in groupNames, assigning
// a fresh one from samba_rid_seq (the same sequence store.CredentialStore
// uses for users, so a user and a group can never collide on one SID) to
// any name seen for the first time. Safe to call on every samba-privileged
// search -- the insert is a no-op once every declared group already has a
// row, the same tradeoff store.CredentialStore.Upsert already makes for
// users.
func (s *SambaGroupStore) EnsureRIDs(ctx context.Context, groupNames []string) (map[string]int64, error) {
	if len(groupNames) == 0 {
		return map[string]int64{}, nil
	}
	rows, err := s.Pool.Query(ctx, `
		WITH ins AS (
			INSERT INTO samba_group_rids (group_name, samba_rid)
			SELECT unnest($1::text[]), nextval('samba_rid_seq')
			ON CONFLICT (group_name) DO NOTHING
		)
		SELECT group_name, samba_rid FROM samba_group_rids WHERE group_name = ANY($1)`,
		groupNames)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]int64, len(groupNames))
	for rows.Next() {
		var name string
		var rid int64
		if err := rows.Scan(&name, &rid); err != nil {
			return nil, err
		}
		out[name] = rid
	}
	return out, rows.Err()
}
