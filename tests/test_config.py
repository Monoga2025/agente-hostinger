"""Unit tests for configuration loading and multi-domain handling."""

import pytest
from hostinger_cli.config import ConfigError, load_config


def test_load_config_valid(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "HOSTINGER_SFTP_HOST=203.0.113.10\n"
        "HOSTINGER_SFTP_PORT=65002\n"
        "HOSTINGER_SFTP_USERNAME=u000000000\n"
        "HOSTINGER_SFTP_PASSWORD=SecretAgentPass99\n"
        "HOSTINGER_TARGET_DOMAIN=grupomonoga.com\n"
        "HOSTINGER_ALLOWED_ROOTS=/home/u000000000/domains/grupomonoga.com/public_html\n"
        "HOSTINGER_BACKUP_DIR=./backups\n"
    )

    cfg = load_config(env_file)
    assert cfg.host == "203.0.113.10"
    assert cfg.port == 65002
    assert cfg.username == "u000000000"
    assert cfg.password == "SecretAgentPass99"
    assert cfg.target_domain == "grupomonoga.com"
    assert cfg.get_root_for_domain() == "/home/u000000000/domains/grupomonoga.com/public_html"


def test_load_config_placeholder_fails(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "HOSTINGER_SFTP_HOST=203.0.113.10\n"
        "HOSTINGER_SFTP_PORT=65002\n"
        "HOSTINGER_SFTP_USERNAME=u000000000\n"
        "HOSTINGER_SFTP_PASSWORD=<contraseña_exclusiva_para_el_agente>\n"
        "HOSTINGER_TARGET_DOMAIN=grupomonoga.com\n"
        "HOSTINGER_ALLOWED_ROOTS=/home/u000000000/domains/grupomonoga.com/public_html\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="HOSTINGER_SFTP_PASSWORD"):
        load_config(env_file)


def test_multi_domain_support(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "HOSTINGER_SFTP_HOST=203.0.113.10\n"
        "HOSTINGER_SFTP_PORT=65002\n"
        "HOSTINGER_SFTP_USERNAME=u000000000\n"
        "HOSTINGER_SFTP_PASSWORD=StrongPassword456\n"
        "HOSTINGER_TARGET_DOMAIN=domainA.com\n"
        "HOSTINGER_ALLOWED_ROOTS=/home/u000000000/domains/domainA.com/public_html,/home/u000000000/domains/domainB.com/public_html\n"
        "HOSTINGER_DOMAINS=domainA.com:/home/u000000000/domains/domainA.com/public_html,domainB.com:/home/u000000000/domains/domainB.com/public_html\n"
    )

    cfg = load_config(env_file)
    assert cfg.get_root_for_domain("domainA.com") == "/home/u000000000/domains/domainA.com/public_html"
    assert cfg.get_root_for_domain("domainB.com") == "/home/u000000000/domains/domainB.com/public_html"


def test_to_safe_dict_masks_password(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "HOSTINGER_SFTP_HOST=203.0.113.10\n"
        "HOSTINGER_SFTP_PORT=65002\n"
        "HOSTINGER_SFTP_USERNAME=u000000000\n"
        "HOSTINGER_SFTP_PASSWORD=SuperSecretString\n"
        "HOSTINGER_TARGET_DOMAIN=grupomonoga.com\n"
        "HOSTINGER_ALLOWED_ROOTS=/home/u000000000/domains/grupomonoga.com/public_html\n"
    )

    cfg = load_config(env_file)
    safe = cfg.to_safe_dict()
    assert "SuperSecretString" not in str(safe)
    assert safe["password"] == "********"
