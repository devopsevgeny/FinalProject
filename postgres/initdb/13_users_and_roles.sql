-- Create enum for role types
CREATE TYPE core.role_type AS ENUM (
    'GLOBAL_ADMIN',
    'SECRET_ADMIN',
    'USER_ADMIN',
    'CONFIG_ADMIN',
    'SECRET_VIEWER',
    'CONFIG_VIEWER',
    'USER_VIEWER'
);

-- Roles table
CREATE TABLE IF NOT EXISTS core.roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name core.role_type NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Users table with extended fields
CREATE TABLE IF NOT EXISTS core.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash BYTEA NOT NULL,
    is_active BOOLEAN DEFAULT true,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- User-roles relationship table (many-to-many)
CREATE TABLE IF NOT EXISTS core.user_roles (
    user_id UUID REFERENCES core.users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES core.roles(id) ON DELETE CASCADE,
    granted_by UUID REFERENCES core.users(id),
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

-- Trigger for updating updated_at column
CREATE OR REPLACE FUNCTION core.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON core.users
    FOR EACH ROW
    EXECUTE FUNCTION core.update_updated_at_column();

-- Initialize base roles
INSERT INTO core.roles (name, description) VALUES
    ('GLOBAL_ADMIN', 'Full system access'),
    ('SECRET_ADMIN', 'Can manage secrets'),
    ('USER_ADMIN', 'Can manage users'),
    ('CONFIG_ADMIN', 'Can manage configurations'),
    ('SECRET_VIEWER', 'Can view secrets'),
    ('CONFIG_VIEWER', 'Can view configurations'),
    ('USER_VIEWER', 'Can view users')
ON CONFLICT DO NOTHING;

-- Create admin user (password: admin)
DO $$
DECLARE
    admin_id UUID;
    global_admin_role_id UUID;
BEGIN
    -- Create admin user
    INSERT INTO core.users (username, email, password_hash)
    VALUES ('admin', 'admin@example.com', digest('admin', 'sha256'))
    ON CONFLICT (username) DO UPDATE
    SET email = EXCLUDED.email
    RETURNING id INTO admin_id;

    -- Get global admin role ID
    SELECT id INTO global_admin_role_id
    FROM core.roles
    WHERE name = 'GLOBAL_ADMIN';

    -- Assign role to admin
    INSERT INTO core.user_roles (user_id, role_id, granted_by)
    VALUES (admin_id, global_admin_role_id, admin_id)
    ON CONFLICT DO NOTHING;
END $$;

-- Function to check user role
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

-- Optimization indexes
CREATE INDEX idx_user_roles_user_id ON core.user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON core.user_roles(role_id);
CREATE INDEX idx_users_email ON core.users(email);
CREATE INDEX idx_users_username ON core.users(username);