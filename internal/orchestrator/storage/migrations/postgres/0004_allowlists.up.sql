CREATE TABLE allowlists (
  id           TEXT PRIMARY KEY,
  scope        TEXT NOT NULL,
  package_name TEXT,
  kind         TEXT NOT NULL,
  value        TEXT NOT NULL,
  note         TEXT NOT NULL DEFAULT '',
  created_at   TIMESTAMPTZ NOT NULL,
  CHECK (scope IN ('global','package')),
  CHECK (kind  IN ('cidr','path','sni')),
  CHECK ((scope='global' AND package_name IS NULL) OR
         (scope='package' AND package_name IS NOT NULL))
);

CREATE INDEX allowlists_by_package ON allowlists (package_name);
CREATE INDEX allowlists_by_scope   ON allowlists (scope);
