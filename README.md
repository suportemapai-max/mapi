# NEXUS

Aplicativo de página única (`index.html`) para guardar e compartilhar acessos de clientes.

- **Dados**: Supabase, só como banco. Cada registro é criptografado no navegador (AES-GCM) com uma chave AES-256 gerada no primeiro uso. O banco guarda só texto cifrado, e a chave só é entregue a usuários ativos que confirmaram o código do **Google Authenticator** (TOTP, nível aal2). Quem tem só e-mail e senha não consegue abrir nada.
- **Aplicativo**: este repositório, publicado no GitHub Pages. O arquivo não contém dados nem segredos. A chave `anon` embutida é pública por desenho.
- **Banco**: `supabase/schema.sql` (tabelas fechadas por RLS; tudo passa por funções que checam perfil e permissão).

Recursos: login por e-mail, perfis (admin, suporte, leitura), permissão por cliente, log de acesso e de cópia, links compartilhados com validade, limite de aberturas, tempo de visualização e cancelamento imediato.

Publicação: Settings → Pages → Deploy from a branch → `main` / root.


## Authenticator
- No primeiro login cada usuário lê um QR Code no Google Authenticator e confirma o código. Depois, todo login pede o código.
- O bloqueio por inatividade também pede o código de novo.
- Pré-requisito no Supabase: Authentication → Sign In / Providers → Multi-Factor → TOTP habilitado (padrão).
- Perdeu o celular? Um administrador do Supabase remove o fator em Authentication → Users → (usuário) → fatores, e a pessoa cadastra de novo.
- Observação: a chave fica guardada no banco e é liberada pelo servidor após o código. Quem tiver acesso administrativo ao projeto Supabase consegue lê-la.
