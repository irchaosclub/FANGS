-- 0004 — operator allowlists.
--
-- Lets operators suppress deviation categories for specific values:
--   * scope='global'  + package_name=NULL  → applies to every run
--   * scope='package' + package_name='X'   → applies only to runs of X
--
-- Three kinds:
--   * cidr  → suppress net_new_destination matches inside the CIDR
--   * path  → suppress fs_new_path_(read|write) starting with the prefix
--   * sni   → suppress net_new_https_host equal to the SNI (case-insens.)
--
-- Differ ANDs the in-DB rules with the hardcoded DefaultCDNAllowlist:
-- a destination is allowed if it matches either source.
CREATE TABLE allowlists (
  id           TEXT PRIMARY KEY,
  scope        TEXT NOT NULL,          -- 'global' | 'package'
  package_name TEXT,                   -- non-NULL iff scope='package'
  kind         TEXT NOT NULL,          -- 'cidr' | 'path' | 'sni'
  value        TEXT NOT NULL,
  note         TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL,
  CHECK (scope IN ('global','package')),
  CHECK (kind  IN ('cidr','path','sni')),
  CHECK ((scope='global' AND package_name IS NULL) OR
         (scope='package' AND package_name IS NOT NULL))
);

CREATE INDEX allowlists_by_package ON allowlists (package_name);
CREATE INDEX allowlists_by_scope   ON allowlists (scope);
