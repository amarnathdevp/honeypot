pub const SENSITIVE_PATHS: &[&str] = &[
    ".env",
    ".git",
    ".git/config",
    ".git/HEAD",
    ".config",
    ".backup",
    ".Backup",
    "config.php",
    "wp-config.php",
    "web.config",
];
pub const PATHS_TRAVERSAL_PATTERNS: &[&str] = &[
    "../",
    "..\\",
    "/etc/passwd",
    "/etc/shadow",
    "boot.ini",
];

pub const XSS_PATTERNS: &[&str] = &[
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    "onclick=",
    "onmouseover=",
    "onfocus=",
    "<iframe",
    "<object",
    "<embed",
];

pub const SQL_INJECTION_PATTERNS: &[&str] = &[
    "' OR 1=1",
    "' OR '1'='1",
    "' OR 1 = 1",
    "UNION SELECT",
    "DROP TABLE",
    "SELECT * FROM",
    "UNION ALL SELECT",
    "INSERT INTO",
    "DELETE FROM",
    "UPDATE SET",
    "ALTER TABLE",
    "CREATE TABLE",
    "TRUNCATE TABLE",
    "SLEEP(",
    "BENCHMARK(",
];



