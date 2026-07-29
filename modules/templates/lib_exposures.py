"""Exposed sensitive files / VCS / secrets / debug endpoints (path templates).

Grounded in nuclei 'exposures' + PayloadsAllTheThings. Each is signature-verified
(status + regex/words) to limit false positives on SPAs that 200 everything.
"""
from __future__ import annotations
from modules.templates.engine import register_templates

CAT = "Exposures"
FIX = "Remove/deny public access to this resource; rotate any exposed secrets."


def P(i, name, path, sev, regex=None, words=None, status=(200,), impact="", fix=FIX):
    m = {"status": list(status)}
    if regex:
        m["regex"] = regex
    if words:
        m["words"] = words
    return {"id": i, "name": name, "type": "path", "path": path, "severity": sev,
            "category": CAT, "match": m, "impact": impact, "remediation": fix,
            "desc": f"Publicly accessible: {path}"}


TEMPLATES = [
    # --- Version control ---
    P("exp_git_config", "Exposed .git/config", "/.git/config", "high", regex=r"\[core\]|\[remote "),
    P("exp_git_head", "Exposed .git/HEAD", "/.git/HEAD", "high", regex=r"^ref:\s"),
    P("exp_git_index", "Exposed .git/index", "/.git/index", "high", regex=r"DIRC"),
    P("exp_git_logs", "Exposed .git/logs/HEAD", "/.git/logs/HEAD", "high", regex=r"commit|clone|checkout"),
    P("exp_svn_wcdb", "Exposed .svn/wc.db", "/.svn/wc.db", "medium", regex=r"SQLite format"),
    P("exp_svn_entries", "Exposed .svn/entries", "/.svn/entries", "medium", regex=r"svn|dir"),
    P("exp_hg", "Exposed .hg/requires", "/.hg/requires", "medium", regex=r"revlog|dotencode|store"),
    P("exp_bzr", "Exposed .bzr/branch-format", "/.bzr/branch-format", "low", regex=r"Bazaar"),
    # --- Env / secrets ---
    P("exp_env", "Exposed .env", "/.env", "critical", regex=r"(APP_KEY|DB_PASSWORD|SECRET|API_KEY|AWS_)"),
    P("exp_env_local", "Exposed .env.local", "/.env.local", "critical", regex=r"(APP_KEY|DB_|SECRET|API_KEY)"),
    P("exp_env_prod", "Exposed .env.production", "/.env.production", "critical", regex=r"(APP_KEY|DB_|SECRET)"),
    P("exp_env_bak", "Exposed .env.bak", "/.env.bak", "critical", regex=r"(APP_KEY|DB_|SECRET)"),
    P("exp_aws_cred", "Exposed AWS credentials", "/.aws/credentials", "critical", regex=r"aws_access_key_id"),
    P("exp_npmrc", "Exposed .npmrc auth token", "/.npmrc", "high", regex=r"_authToken|_password"),
    P("exp_dockercfg", "Exposed .dockercfg", "/.dockercfg", "high", regex=r"\"auth\"|\"email\""),
    P("exp_docker_config", "Exposed docker config.json", "/.docker/config.json", "high", regex=r"\"auths\""),
    P("exp_htpasswd", "Exposed .htpasswd", "/.htpasswd", "high", regex=r":\$(apr1|2y|1)\$"),
    P("exp_netrc", "Exposed .netrc", "/.netrc", "high", regex=r"machine .* login .* password"),
    P("exp_ssh_key", "Exposed private key", "/id_rsa", "critical", regex=r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----"),
    P("exp_pgpass", "Exposed .pgpass", "/.pgpass", "high", regex=r":\w+:\w+:\w+:"),
    # --- Config / backups ---
    P("exp_wpconfig_bak", "WordPress config backup", "/wp-config.php.bak", "critical", regex=r"DB_PASSWORD|<\?php"),
    P("exp_wpconfig_save", "wp-config.php.save", "/wp-config.php.save", "critical", regex=r"DB_PASSWORD|<\?php"),
    P("exp_wpconfig_orig", "wp-config.php.orig", "/wp-config.php.orig", "critical", regex=r"DB_PASSWORD|<\?php"),
    P("exp_config_php_bak", "config.php backup", "/config.php.bak", "high", regex=r"<\?php|define\("),
    P("exp_config_old", "config.old", "/config.old", "high", regex=r"password|secret|<\?php"),
    P("exp_web_config", "Exposed web.config", "/web.config", "medium", regex=r"<configuration|connectionStrings"),
    P("exp_appsettings", "Exposed appsettings.json", "/appsettings.json", "high", regex=r"ConnectionStrings|\"Password\""),
    P("exp_sql_dump", "Exposed SQL dump", "/dump.sql", "high", regex=r"INSERT INTO|CREATE TABLE|DROP TABLE"),
    P("exp_db_sql", "Exposed database.sql", "/database.sql", "high", regex=r"INSERT INTO|CREATE TABLE"),
    P("exp_backup_sql", "Exposed backup.sql", "/backup.sql", "high", regex=r"INSERT INTO|CREATE TABLE"),
    # --- CI / build metadata ---
    P("exp_gitlab_ci", "Exposed .gitlab-ci.yml", "/.gitlab-ci.yml", "low", regex=r"stages:|script:"),
    P("exp_travis", "Exposed .travis.yml", "/.travis.yml", "low", regex=r"language:|script:"),
    P("exp_dockerfile", "Exposed Dockerfile", "/Dockerfile", "low", regex=r"^FROM |RUN |COPY "),
    P("exp_docker_compose", "Exposed docker-compose.yml", "/docker-compose.yml", "medium", regex=r"services:|image:"),
    P("exp_composer", "Exposed composer.json", "/composer.json", "info", regex=r"\"require\""),
    P("exp_composer_lock", "Exposed composer.lock", "/composer.lock", "info", regex=r"\"packages\""),
    # --- IDE / editor ---
    P("exp_dsstore", "Exposed .DS_Store", "/.DS_Store", "low", regex=r"Bud1|\x00\x00\x00\x01Bud1"),
    P("exp_idea", "Exposed .idea/workspace.xml", "/.idea/workspace.xml", "low", regex=r"<project|<component"),
    P("exp_vscode_sftp", "Exposed .vscode/sftp.json", "/.vscode/sftp.json", "high", regex=r"\"password\"|\"privateKeyPath\""),
    # --- Debug / info ---
    P("exp_phpinfo", "Exposed phpinfo()", "/phpinfo.php", "medium", regex=r"phpinfo\(\)|PHP Version"),
    P("exp_info_php", "Exposed info.php", "/info.php", "medium", regex=r"phpinfo\(\)|PHP Version"),
    P("exp_server_status", "Apache server-status", "/server-status", "medium", regex=r"Apache Server Status|Server uptime"),
    P("exp_server_info", "Apache server-info", "/server-info", "medium", regex=r"Apache Server Information|Server Settings"),
    P("exp_elmah", "Exposed ELMAH log", "/elmah.axd", "high", regex=r"Error Log for|ELMAH"),
    P("exp_trace_axd", "ASP.NET trace.axd", "/trace.axd", "medium", regex=r"Application Trace|Requests to this"),
    P("exp_metrics", "Exposed Prometheus /metrics", "/metrics", "low", regex=r"# HELP |# TYPE "),
    P("exp_expvar", "Exposed Go /debug/vars", "/debug/vars", "medium", regex=r"\"cmdline\"|\"memstats\""),
    # --- Misc ---
    P("exp_security_txt", "security.txt present", "/.well-known/security.txt", "info", regex=r"Contact:"),
    P("exp_crossdomain", "Adobe crossdomain.xml", "/crossdomain.xml", "info", regex=r"cross-domain-policy|allow-access-from"),
    P("exp_wsftp_log", "WS_FTP.LOG exposed", "/WS_FTP.LOG", "low", regex=r"WS_FTP|transferred"),
]

register_templates(TEMPLATES)
