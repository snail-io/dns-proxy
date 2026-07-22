package storage

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/go-dns-proxy/dns-proxy/internal/crypto"
	"github.com/go-dns-proxy/dns-proxy/internal/model"
	_ "modernc.org/sqlite"
)

const (
	authKey     = "93a8b2c9d1e4f5asnail0d2e3f4aed6c"
	adminUserKey = "admin_user"
	adminPassKey = "admin_pass"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	_ = path
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS domain_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT NOT NULL,
			mode TEXT NOT NULL DEFAULT 'suffix',
			upstream TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_rules_domain ON domain_rules(domain)`,
		`CREATE TABLE IF NOT EXISTS app_config (
			key TEXT PRIMARY KEY,
			value TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS host_records (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'A',
			match_mode TEXT NOT NULL DEFAULT 'exact',
			value TEXT NOT NULL,
			ttl INTEGER NOT NULL DEFAULT 300,
			comment TEXT,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_hosts_domain ON host_records(domain)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}

	// ALTER TABLE 兼容老 DB（若列已存在则忽略错误）
	if _, err := s.db.Exec(`ALTER TABLE host_records ADD COLUMN match_mode TEXT NOT NULL DEFAULT 'exact'`); err != nil {
		// 列已存在时 sqlite 返回 duplicate column，忽略
	}

	return s.initAdminAccount()
}

func (s *Store) initAdminAccount() error {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM app_config WHERE key IN (?, ?)`, adminUserKey, adminPassKey).Scan(&count)
	if err != nil {
		return err
	}
	if count == 2 {
		return nil
	}

	encryptedUser, err := crypto.EncryptAES("admin", authKey)
	if err != nil {
		return err
	}
	encryptedPass, err := crypto.EncryptAES("123456", authKey)
	if err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`INSERT OR REPLACE INTO app_config(key, value) VALUES(?, ?)`, adminUserKey, encryptedUser)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT OR REPLACE INTO app_config(key, value) VALUES(?, ?)`, adminPassKey, encryptedPass)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) GetAdminUser(ctx context.Context) (string, error) {
	var encryptedUser string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM app_config WHERE key = ?`, adminUserKey).Scan(&encryptedUser)
	if err != nil {
		return "", err
	}
	return crypto.DecryptAES(encryptedUser, authKey)
}

func (s *Store) GetAdminPass(ctx context.Context) (string, error) {
	var encryptedPass string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM app_config WHERE key = ?`, adminPassKey).Scan(&encryptedPass)
	if err != nil {
		return "", err
	}
	return crypto.DecryptAES(encryptedPass, authKey)
}

func (s *Store) UpdateAdminAccount(ctx context.Context, user, pass string) error {
	encryptedUser, err := crypto.EncryptAES(user, authKey)
	if err != nil {
		return err
	}
	encryptedPass, err := crypto.EncryptAES(pass, authKey)
	if err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `UPDATE app_config SET value = ? WHERE key = ?`, encryptedUser, adminUserKey)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE app_config SET value = ? WHERE key = ?`, encryptedPass, adminPassKey)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func rowToRule(row *sql.Row) (model.DomainRule, error) {
	var r model.DomainRule
	var enabledInt int
	var createdAt, updatedAt string
	err := row.Scan(&r.ID, &r.Domain, &r.Mode, &r.Upstream, &enabledInt, &createdAt, &updatedAt)
	if err != nil {
		return r, err
	}
	r.Enabled = enabledInt == 1
	r.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	r.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
	return r, nil
}

func rowsToRules(rows *sql.Rows) ([]model.DomainRule, error) {
	defer rows.Close()
	var out []model.DomainRule
	for rows.Next() {
		var r model.DomainRule
		var enabledInt int
		var createdAt, updatedAt string
		if err := rows.Scan(&r.ID, &r.Domain, &r.Mode, &r.Upstream, &enabledInt, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		r.Enabled = enabledInt == 1
		r.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		r.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) ListRules(ctx context.Context) ([]model.DomainRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, domain, mode, upstream, enabled, created_at, updated_at FROM domain_rules ORDER BY domain ASC`)
	if err != nil {
		return nil, err
	}
	return rowsToRules(rows)
}

func (s *Store) GetRule(ctx context.Context, id int64) (model.DomainRule, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, domain, mode, upstream, enabled, created_at, updated_at FROM domain_rules WHERE id = ?`, id)
	return rowToRule(row)
}

func (s *Store) CreateRule(ctx context.Context, c model.RuleCreate) (model.DomainRule, error) {
	enabled := 1
	if c.Enabled != nil {
		if !*c.Enabled {
			enabled = 0
		}
	}
	mode := c.Mode
	if mode != "exact" && mode != "suffix" {
		mode = "suffix"
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO domain_rules(domain, mode, upstream, enabled) VALUES(?,?,?,?)`,
		c.Domain, mode, c.Upstream, enabled,
	)
	if err != nil {
		return model.DomainRule{}, err
	}
	id, _ := res.LastInsertId()
	return s.GetRule(ctx, id)
}

func (s *Store) UpdateRule(ctx context.Context, id int64, u model.RuleUpdate) (model.DomainRule, error) {
	cur, err := s.GetRule(ctx, id)
	if err != nil {
		return cur, err
	}
	if u.Domain != nil {
		cur.Domain = *u.Domain
	}
	if u.Mode != nil {
		cur.Mode = *u.Mode
	}
	if u.Upstream != nil {
		cur.Upstream = *u.Upstream
	}
	if u.Enabled != nil {
		cur.Enabled = *u.Enabled
	}
	enabled := 0
	if cur.Enabled {
		enabled = 1
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE domain_rules SET domain=?, mode=?, upstream=?, enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		cur.Domain, cur.Mode, cur.Upstream, enabled, id,
	)
	if err != nil {
		return cur, err
	}
	return s.GetRule(ctx, id)
}

func (s *Store) DeleteRule(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM domain_rules WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("not found")
	}
	return nil
}

func normalizeMatchMode(m string) string {
	m = strings.ToLower(strings.TrimSpace(m))
	if m == "" {
		return "exact"
	}
	if m != "exact" && m != "suffix" {
		return "exact"
	}
	return m
}

func rowToHost(row *sql.Row) (model.HostRecord, error) {
	var r model.HostRecord
	var enabledInt int
	var createdAt, updatedAt string
	err := row.Scan(&r.ID, &r.Domain, &r.Type, &r.MatchMode, &r.Value, &r.TTL, &r.Comment, &enabledInt, &createdAt, &updatedAt)
	if err != nil {
		return r, err
	}
	r.Enabled = enabledInt == 1
	if r.MatchMode == "" {
		r.MatchMode = "exact"
	}
	r.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	r.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
	return r, nil
}

func rowsToHosts(rows *sql.Rows) ([]model.HostRecord, error) {
	defer rows.Close()
	var out []model.HostRecord
	for rows.Next() {
		var r model.HostRecord
		var enabledInt int
		var createdAt, updatedAt string
		if err := rows.Scan(&r.ID, &r.Domain, &r.Type, &r.MatchMode, &r.Value, &r.TTL, &r.Comment, &enabledInt, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		r.Enabled = enabledInt == 1
		if r.MatchMode == "" {
			r.MatchMode = "exact"
		}
		r.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		r.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) ListHosts(ctx context.Context) ([]model.HostRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, domain, type, match_mode, value, ttl, comment, enabled, created_at, updated_at FROM host_records ORDER BY domain ASC, type ASC`)
	if err != nil {
		return nil, err
	}
	return rowsToHosts(rows)
}

func (s *Store) GetHost(ctx context.Context, id int64) (model.HostRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, domain, type, match_mode, value, ttl, comment, enabled, created_at, updated_at FROM host_records WHERE id = ?`, id)
	return rowToHost(row)
}

func (s *Store) CreateHost(ctx context.Context, c model.HostCreate) (model.HostRecord, error) {
	enabled := 1
	if c.Enabled != nil {
		if !*c.Enabled {
			enabled = 0
		}
	}
	ttl := 300
	if c.TTL != nil {
		ttl = *c.TTL
		if ttl < 0 {
			ttl = 0
		}
	}
	t := strings.ToUpper(strings.TrimSpace(c.Type))
	if t == "" {
		t = "A"
	}
	matchMode := normalizeMatchMode(c.MatchMode)
	comment := c.Comment
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO host_records(domain, type, match_mode, value, ttl, comment, enabled) VALUES(?,?,?,?,?,?,?)`,
		c.Domain, t, matchMode, c.Value, ttl, comment, enabled,
	)
	if err != nil {
		return model.HostRecord{}, err
	}
	id, _ := res.LastInsertId()
	return s.GetHost(ctx, id)
}

func (s *Store) UpdateHost(ctx context.Context, id int64, u model.HostUpdate) (model.HostRecord, error) {
	cur, err := s.GetHost(ctx, id)
	if err != nil {
		return cur, err
	}
	if u.Domain != nil {
		cur.Domain = *u.Domain
	}
	if u.Type != nil {
		cur.Type = strings.ToUpper(strings.TrimSpace(*u.Type))
		if cur.Type == "" {
			cur.Type = "A"
		}
	}
	if u.MatchMode != nil {
		cur.MatchMode = normalizeMatchMode(*u.MatchMode)
	}
	if u.Value != nil {
		cur.Value = *u.Value
	}
	if u.TTL != nil {
		cur.TTL = *u.TTL
		if cur.TTL < 0 {
			cur.TTL = 0
		}
	}
	if u.Comment != nil {
		cur.Comment = *u.Comment
	}
	if u.Enabled != nil {
		cur.Enabled = *u.Enabled
	}
	enabled := 0
	if cur.Enabled {
		enabled = 1
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE host_records SET domain=?, type=?, match_mode=?, value=?, ttl=?, comment=?, enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		cur.Domain, cur.Type, cur.MatchMode, cur.Value, cur.TTL, cur.Comment, enabled, id,
	)
	if err != nil {
		return cur, err
	}
	return s.GetHost(ctx, id)
}

func (s *Store) DeleteHost(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM host_records WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("not found")
	}
	return nil
}
