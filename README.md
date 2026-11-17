# Security Guard para GLPI

> [!WARNING]
> **Status: Em Desenvolvimento (Beta / Pré-homologação)**
> Este plugin teve a arquitetura, a segurança e os fluxos validados por revisão de código, auditoria de segurança e testes unitários automatizados em CI (`PHP 7.4–8.3` com mocks de GLPI 10/11/12), mas **ainda não foi testado em uma instância GLPI ao vivo**. Valide em ambiente de homologação antes de usar em produção e reporte eventuais ajustes via Issues.

Proteção contra força bruta na autenticação (Web e REST API), bloqueio temporário por conta/IP e trilha de auditoria de eventos críticos de segurança para **GLPI 10, 11 e 12**.

## Funcionalidades

- **Proteção Pré-Login contra Força Bruta:**
  - Monitora tentativas de autenticação no login web (`front/login.php`, compatível com `login_name` no GLPI 11/12 e campo dinâmico `$_SESSION['namfield']` no GLPI 10) e na API REST (`/apirest.php/initSession`).
  - Bloqueia requisições de pares `(usuário, IP)` ou IPs temporariamente bloqueados no hook `post_init` **antes** da execução de `Auth::login()`, evitando consumo desnecessário de CPU, banco de dados e consultas LDAP.
  - Em caso de sucesso (`init_session`), limpa automaticamente o contador de falhas acumuladas para o par `(usuário, IP)`.
- **Resolução Segura de Endereço IP & Allowlist:**
  - Utiliza estritamente `$_SERVER['REMOTE_ADDR']` por padrão, evitando falsificação do cabeçalho `X-Forwarded-For`.
  - Suporta leitura de `X-Forwarded-For` somente quando `trust_proxy = 1` está ativo **e** `REMOTE_ADDR` pertence à lista configurada de proxies reversos confiáveis (`trusted_proxies`, com suporte a IPv4, IPv6 e CIDR).
  - Suporta lista de permissão (`ip_allowlist`) para garantir que IPs ou sub-redes administrativas nunca sejam bloqueados.
- **Auditoria de Alterações Sensíveis:**
  - Registra eventos de atribuição e remoção de perfis (`Profile_User`), destacando com severidade `critical` perfis com permissão administrativa (`config:UPDATE`).
  - Audita criação de usuários (`user_created`), mudanças de status (`is_active` / `is_deleted`), exclusão permanente (`user_purged`), redefinição de senha (`password_changed`) e rotação de tokens (`token_changed`) **sem jamais gravar hashes de senha ou valores de tokens**.
- **Painel Administrativo (`Configurar > Plug-ins > Security Guard`):**
  - Ajuste de janela de observação, limite de tentativas, duração do bloqueio, proxies confiáveis, allowlist e retenção de logs.
  - Desbloqueio manual imediato de contas/IPs bloqueados e expurgo sob demanda de logs antigos.

## Matriz de Compatibilidade

| Versão do GLPI | Versão do PHP | Status |
| :--- | :--- | :--- |
| **GLPI 10.0.x** (`10.0.0` – `10.0.99`) | PHP `7.4` ou superior | Suportado |
| **GLPI 11.0.x** (`11.0.0` – `11.0.99`) | PHP `8.2` ou superior | Suportado |
| **GLPI 12.0.x** (`12.0.0` – `12.0.99`) | PHP `8.3` ou superior | Suportado |

## Instalação

1. Extraia o diretório `securityguard` dentro da pasta `plugins/` (ou `marketplace/` no GLPI 10) da sua instalação do GLPI.
2. Acesse **Configurar > Plug-ins** no GLPI.
3. Clique em **Instalar** e em seguida em **Ativar** no plugin **Security Guard**.
4. Acesse a página de configuração do plugin para ajustar os limites de bloqueio e a política de auditoria.

## Licença

Distribuído sob a licença **GNU General Public License v3.0 or later (`GPL-3.0-or-later` / `GPLv3+`)**.  
Copyright (C) 2026 by G. Martins.
