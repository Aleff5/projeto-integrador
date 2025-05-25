-- Usuários
CREATE TABLE users (
    firebase_uid VARCHAR PRIMARY KEY,
    display_name VARCHAR NOT NULL,
    email VARCHAR,
    password VARCHAR
);

-- Workspaces
CREATE TABLE workspaces (
    id SERIAL PRIMARY KEY,
    name VARCHAR,
    description VARCHAR,
    is_public BOOLEAN DEFAULT FALSE,
    owner_uid VARCHAR NOT NULL REFERENCES users(firebase_uid),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    members INT DEFAULT 1
);

-- Convites para workspaces
CREATE TABLE workspace_invites (
    id SERIAL PRIMARY KEY,
    workspace_id INT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    invite_code VARCHAR UNIQUE NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP,
    role VARCHAR DEFAULT 'member'
);

-- Relação usuário → workspace
CREATE TABLE user_workspace (
    workspace_id INT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id VARCHAR NOT NULL REFERENCES users(firebase_uid) ON DELETE CASCADE,
    role VARCHAR DEFAULT 'member',
    joined_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (workspace_id, user_id)
);

-- Notas / Eventos / Arquivos
CREATE TABLE notes (
    id SERIAL PRIMARY KEY,
    workspace_id INT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id VARCHAR NOT NULL REFERENCES users(firebase_uid) ON DELETE CASCADE,
    title VARCHAR NOT NULL,
    type VARCHAR CHECK (type IN ('note', 'event', 'reminder', 'file')) DEFAULT 'note',
    status VARCHAR CHECK (status IN ('active', 'completed', 'archived')) DEFAULT 'active',
    start_date TIMESTAMP,
    end_date TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
