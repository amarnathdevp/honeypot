CREATE TABLE IF NOT EXISTS alerts (
                                      id SERIAL PRIMARY KEY,
                                      method VARCHAR(20) NOT NULL,
    path TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    query TEXT,
    attack_type VARCHAR(100) NOT NULL,
    risk VARCHAR(20) NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );