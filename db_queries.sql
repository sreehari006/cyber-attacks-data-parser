CREATE DATABASE cyber_security;

CREATE SCHEMA attacks_repo;

CREATE TABLE attacks_repo.ransomware (
    uid SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    decryptor TEXT,
    screenshots TEXT,
    ms_detection TEXT,
    ms_info TEXT,
    sandbox TEXT,
    iocs TEXT,
    snort TEXT,
    CONSTRAINT unique_ransomeware_name UNIQUE (name)
);

CREATE TABLE attacks_repo.ransomware_alias (
    uid SERIAL PRIMARY KEY,
    parent_id INT NOT NULL,
    alias TEXT,
    FOREIGN KEY (parent_id) REFERENCES attacks_repo.ransomware (uid),
    CONSTRAINT unique_ransomware_alias UNIQUE (alias)
);

CREATE TABLE attacks_repo.ransomware_ext (
    uid SERIAL PRIMARY KEY,
    parent_id INT NOT NULL,
    ext TEXT,
    FOREIGN KEY (parent_id) REFERENCES attacks_repo.ransomware (uid),
    CONSTRAINT unique_ransomware_ext UNIQUE (parent_id, ext)
);

CREATE TABLE attacks_repo.ransomware_ext_pattern (
    uid SERIAL PRIMARY KEY,
    parent_id INT NOT NULL,
    ext_pattern TEXT,
    FOREIGN KEY (parent_id) REFERENCES attacks_repo.ransomware (uid),
    CONSTRAINT unique_ransomware_ext_pattern UNIQUE (parent_id, ext_pattern)
);

CREATE TABLE attacks_repo.ransomware_notes (
    uid SERIAL PRIMARY KEY,
    parent_id INT NOT NULL,
    notes TEXT,
    FOREIGN KEY (parent_id) REFERENCES attacks_repo.ransomware (uid),
    CONSTRAINT unique_ransomware_notes UNIQUE (parent_id, notes)
);

CREATE TABLE attacks_repo.ransomware_comments (
    uid SERIAL PRIMARY KEY,
    parent_id INT NOT NULL,
    comments TEXT,
    FOREIGN KEY (parent_id) REFERENCES attacks_repo.ransomware (uid),
    CONSTRAINT unique_ransomware_comments UNIQUE (parent_id, comments)
);

CREATE TABLE attacks_repo.ransomware_algo (
    uid SERIAL PRIMARY KEY,
    parent_id INT NOT NULL,
    algo TEXT,
    FOREIGN KEY (parent_id) REFERENCES attacks_repo.ransomware (uid),
    CONSTRAINT unique_ransomware_algo UNIQUE (parent_id, algo)
);

CREATE TABLE attacks_repo.ransomware_resources (
    uid SERIAL PRIMARY KEY,
    parent_id INT NOT NULL,
    resources TEXT,
    FOREIGN KEY (parent_id) REFERENCES attacks_repo.ransomware (uid),
    CONSTRAINT unique_ransomware_resources UNIQUE (parent_id, resources)
);



