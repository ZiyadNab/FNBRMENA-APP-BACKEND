-- Drop existing tables
DROP TABLE IF EXISTS EGS CASCADE;
DROP TABLE IF EXISTS Sessions CASCADE;
DROP TABLE IF EXISTS Bookmarks CASCADE;
DROP TABLE IF EXISTS Reminders CASCADE;
DROP TABLE IF EXISTS Users CASCADE;

-- Create the `Users` Table
CREATE TABLE Users (
    id text PRIMARY KEY DEFAULT REPLACE(uuid_generate_v4()::text, '-', '' ),
    email CHARACTER VARYING(255) UNIQUE NOT NULL,
    displayname CHARACTER VARYING(255) NOT NULL,
    password CHARACTER VARYING(255) NOT NULL,
    account_created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITHOUT TIME ZONE,
    superuser BOOLEAN DEFAULT FALSE,
    banned BOOLEAN DEFAULT FALSE,
    login_history TIMESTAMP WITHOUT TIME ZONE[] DEFAULT '{}'
);

-- Create the `Reminders` Table
CREATE TABLE Reminders (
    user_id text REFERENCES Users(id) ON DELETE CASCADE,
    cosmetic_id CHARACTER VARYING(255),
    reminder_date TIMESTAMP WITHOUT TIME ZONE,
    PRIMARY KEY (user_id, cosmetic_id, reminder_date)
);

-- Create the `Bookmarks` Table
CREATE TABLE Bookmarks (
    user_id text REFERENCES Users(id) ON DELETE CASCADE,
    cosmetic_id CHARACTER VARYING(255),
    PRIMARY KEY (user_id, cosmetic_id)
);

-- Create the `Sessions` Table
CREATE TABLE Sessions (
    user_id text REFERENCES Users(id) ON DELETE CASCADE,
    session_id text PRIMARY KEY DEFAULT REPLACE(uuid_generate_v4()::text, '-', '' ),
    jwt_token TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITHOUT TIME ZONE,
    UNIQUE(user_id, session_id)
);

-- Create the `EGS` Table
CREATE TABLE EGS (
    user_id text REFERENCES Users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    secret TEXT NOT NULL,
    token JSON DEFAULT NULL,
    PRIMARY KEY (user_id, device_id, account_id, secret)
);
