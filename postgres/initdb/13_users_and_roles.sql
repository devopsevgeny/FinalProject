BEGIN;

-- Предварительные настройки
CREATE SCHEMA IF NOT EXISTS core;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Создание перечисления ролей (если не существует)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_type t
    WHERE t.typname = 'role_type' AND t.typnamespace = 'core'::regnamespace
  ) THEN
    CREATE TYPE core.role_type AS ENUM (
      'GLOBAL_ADMIN','SECRET_ADMIN','USER_ADMIN','CONFIG_ADMIN',
      'SECRET_VIEWER','CONFIG_VIEWER','USER_VIEWER'
    );
  END IF;
END$$;

-- Таблицы
CREATE TABLE IF NOT EXISTS core.roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name core.role_type NOT NULL,
  description TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS core.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash BYTEA NOT NULL,
  is_active BOOLEAN DEFAULT true,
  last_login TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS core.user_roles (
  user_id UUID REFERENCES core.users(id) ON DELETE CASCADE,
  role_id UUID REFERENCES core.roles(id) ON DELETE CASCADE,
  granted_by UUID REFERENCES core.users(id),
  granted_at TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (user_id, role_id)
);

-- Триггер для обновления updated_at
CREATE OR REPLACE FUNCTION core.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_users_updated_at ON core.users;
CREATE TRIGGER update_users_updated_at
  BEFORE UPDATE ON core.users
  FOR EACH ROW
  EXECUTE FUNCTION core.update_updated_at_column();

-- Уникальный индекс для ролей
CREATE UNIQUE INDEX IF NOT EXISTS ux_roles_name ON core.roles(name);

-- Базовые роли
INSERT INTO core.roles (name, description) VALUES
  ('GLOBAL_ADMIN','Полный доступ к системе'),
  ('SECRET_ADMIN','Может управлять секретами'),
  ('USER_ADMIN','Может управлять пользователями'),
  ('CONFIG_ADMIN','Может управлять конфигурациями'),
  ('SECRET_VIEWER','Может просматривать секреты'),
  ('CONFIG_VIEWER','Может просматривать конфигурации'),
  ('USER_VIEWER','Может просматривать пользователей')
ON CONFLICT DO NOTHING;

-- Пользователь admin с ролью GLOBAL_ADMIN
WITH upsert_user AS (
  INSERT INTO core.users (username, email, password_hash)
  VALUES ('admin', 'admin@example.com', digest('admin', 'sha256'))
  ON CONFLICT (username) DO UPDATE
    SET email = EXCLUDED.email,
        password_hash = EXCLUDED.password_hash
  RETURNING id
)
INSERT INTO core.user_roles (user_id, role_id, granted_by)
SELECT u.id, r.id, u.id
FROM upsert_user u
JOIN core.roles r ON r.name = 'GLOBAL_ADMIN'
WHERE NOT EXISTS (
  SELECT 1
  FROM core.user_roles ur
  WHERE ur.user_id = u.id
    AND ur.role_id = (SELECT id FROM core.roles WHERE name = 'GLOBAL_ADMIN')
)
ON CONFLICT DO NOTHING;

-- Функция для проверки роли
CREATE OR REPLACE FUNCTION core.has_role(p_user_id UUID, p_role core.role_type)
RETURNS BOOLEAN AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1
    FROM core.user_roles ur
    JOIN core.roles r ON r.id = ur.role_id
    WHERE ur.user_id = p_user_id
      AND r.name = p_role
  );
END;
$$ LANGUAGE plpgsql;

-- Полезные индексы
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON core.user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON core.user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON core.users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON core.users(username);

COMMIT;