# Changelog

Todas as alterações relevantes deste projeto são documentadas neste arquivo.

## [1.0.0] - 2026-11-16

### Adicionado
- Proteção contra força bruta no login web (`front/login.php`) e REST API (`apirest.php/initSession`) com bloqueio pré-autenticação (`post_init`) e limpeza automática em `init_session`.
- Resolução segura de IP do cliente com validação de proxies reversos confiáveis (`trust_proxy` + `trusted_proxies`) e lista de permissão (`ip_allowlist`) com suporte a IPv4, IPv6 e CIDR.
- Auditoria de segurança para atribuição/remoção de perfis (`Profile_User`) e alterações críticas de contas (`User`: criação, status, senha, rotação de tokens e expurgo).
- Painel administrativo (`front/config.form.php`) com desbloqueio manual, expurgo por retenção e visualização dos bloqueios ativos e últimos 100 eventos.
- Compatibilidade unificada para GLPI 10.0.0 a 12.0.99 e PHP 7.4 a 8.3+.
