"""More exposed files: keys, cloud creds, VCS refs, IaC state, logs, framework
configs. Signature-verified (status + regex) to keep false positives low.
"""
from __future__ import annotations
from modules.templates.engine import register_templates

CAT = "Exposures"
FIX = "Remove/deny public access; rotate any exposed secret."
PK = r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"


def P(i, name, path, sev, regex, status=(200,), impact=""):
    return {"id": i, "name": name, "type": "path", "path": path, "severity": sev,
            "category": CAT, "match": {"status": list(status), "regex": regex},
            "impact": impact, "remediation": FIX, "desc": f"Publicly accessible: {path}"}


TEMPLATES = [
    # Private keys / certs
    P("exp2_server_key", "Exposed server.key", "/server.key", "critical", PK),
    P("exp2_privkey_pem", "Exposed privkey.pem", "/privkey.pem", "critical", PK),
    P("exp2_private_key", "Exposed private.key", "/private.key", "critical", PK),
    P("exp2_id_dsa", "Exposed id_dsa", "/id_dsa", "critical", PK),
    P("exp2_id_ecdsa", "Exposed id_ecdsa", "/id_ecdsa", "critical", PK),
    P("exp2_id_ed25519", "Exposed id_ed25519", "/id_ed25519", "critical", PK),
    # Cloud / service creds
    P("exp2_gcp_sa", "Exposed GCP service account", "/service-account.json", "critical", r"\"private_key\"|\"client_email\""),
    P("exp2_gcp_cred", "Exposed credentials.json (GCP)", "/credentials.json", "high", r"\"private_key\"|\"client_email\"|\"refresh_token\""),
    P("exp2_firebase", "Exposed firebase config", "/.firebaserc", "low", r"\"projects\""),
    P("exp2_aws_exports", "Exposed aws-exports.js", "/aws-exports.js", "medium", r"aws_project_region|amazonaws|aws_cognito"),
    P("exp2_git_credentials", "Exposed .git-credentials", "/.git-credentials", "critical", r"https?://[^:]+:[^@]+@"),
    # VCS refs
    P("exp2_git_master", "Exposed .git/refs/heads/master", "/.git/refs/heads/master", "high", r"^[a-f0-9]{40}"),
    P("exp2_git_main", "Exposed .git/refs/heads/main", "/.git/refs/heads/main", "high", r"^[a-f0-9]{40}"),
    P("exp2_git_packed", "Exposed .git/packed-refs", "/.git/packed-refs", "high", r"refs/(heads|tags)/"),
    P("exp2_gitconfig", "Exposed .gitconfig", "/.gitconfig", "medium", r"\[user\]|\[core\]|\[credential\]"),
    # IaC / CI
    P("exp2_tfstate", "Exposed terraform.tfstate", "/terraform.tfstate", "high", r"\"terraform_version\"|\"resources\""),
    P("exp2_tfstate2", "Exposed .terraform state", "/.terraform/terraform.tfstate", "high", r"\"terraform_version\""),
    P("exp2_kubeconfig", "Exposed .kube/config", "/.kube/config", "critical", r"apiVersion|clusters:|client-certificate-data"),
    P("exp2_circleci", "Exposed .circleci/config.yml", "/.circleci/config.yml", "low", r"^version:|jobs:|workflows:"),
    P("exp2_drone", "Exposed .drone.yml", "/.drone.yml", "low", r"kind:\s*pipeline|steps:"),
    P("exp2_jenkinsfile", "Exposed Jenkinsfile", "/Jenkinsfile", "low", r"pipeline\s*\{|node\s*\{|stage\("),
    # Framework configs
    P("exp2_rails_db", "Exposed Rails database.yml", "/config/database.yml", "high", r"adapter:|password:|database:"),
    P("exp2_rails_secrets", "Exposed Rails secrets.yml", "/config/secrets.yml", "critical", r"secret_key_base"),
    P("exp2_rails_master", "Exposed Rails master.key", "/config/master.key", "critical", r"^[a-f0-9]{32}"),
    P("exp2_web_xml", "Exposed WEB-INF/web.xml", "/WEB-INF/web.xml", "high", r"<web-app|<servlet|<context-param"),
    P("exp2_spring_ctx", "Exposed applicationContext.xml", "/WEB-INF/applicationContext.xml", "medium", r"<beans|springframework"),
    P("exp2_php_ini", "Exposed php.ini", "/php.ini", "medium", r"memory_limit|display_errors|post_max_size"),
    P("exp2_nginx_conf", "Exposed nginx.conf", "/nginx.conf", "medium", r"server\s*\{|location\s|upstream\s"),
    P("exp2_httpd_conf", "Exposed httpd.conf", "/httpd.conf", "medium", r"<VirtualHost|DocumentRoot|LoadModule"),
    # Logs / history
    P("exp2_bash_history", "Exposed .bash_history", "/.bash_history", "medium", r"(^|\n)(sudo |ssh |curl |wget |mysql -|export )"),
    P("exp2_mysql_history", "Exposed .mysql_history", "/.mysql_history", "medium", r"SELECT |INSERT INTO|CREATE TABLE|GRANT "),
    P("exp2_wp_debug", "Exposed wp-content/debug.log", "/wp-content/debug.log", "medium", r"PHP (Notice|Warning|Fatal)|stack trace"),
    P("exp2_error_log", "Exposed error_log", "/error_log", "medium", r"PHP (Warning|Fatal|Parse)|\[error\]"),
    P("exp2_npm_debug", "Exposed npm-debug.log", "/npm-debug.log", "low", r"npm ERR!|verbose stack"),
    # Backups / editor sync
    P("exp2_sftp_config", "Exposed sftp-config.json", "/sftp-config.json", "high", r"\"host\"|\"password\"|\"user\""),
    P("exp2_ftpsync", "Exposed ftpsync.settings", "/ftpsync.settings", "high", r"\"host\"|\"password\""),
    P("exp2_wpconfig_bak2", "Exposed wp-config.php~", "/wp-config.php~", "critical", r"DB_PASSWORD|<\?php"),
    P("exp2_index_bak", "Exposed index.php.bak", "/index.php.bak", "medium", r"<\?php"),
    P("exp2_env_example", "Exposed .env.example", "/.env.example", "info", r"APP_(ENV|KEY)|DB_(HOST|DATABASE)"),
    # Well-known
    P("exp2_openid_config", "OpenID configuration", "/.well-known/openid-configuration", "info", r"authorization_endpoint|issuer|jwks_uri"),
    P("exp2_assetlinks", "Android assetlinks.json", "/.well-known/assetlinks.json", "info", r"package_name|sha256_cert_fingerprints|relation"),
    P("exp2_aasa", "Apple app-site-association", "/.well-known/apple-app-site-association", "info", r"applinks|appID|webcredentials"),
]

register_templates(TEMPLATES)
