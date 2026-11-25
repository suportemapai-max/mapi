# Cofre de Acessos MAP

Aplicativo de página única (`index.html`) para guardar e compartilhar acessos de clientes.

- **Dados**: Supabase, só como banco. Cada registro é criptografado no navegador (AES-GCM) com a "chave do cofre". O banco guarda apenas texto cifrado.
- **Aplicativo**: este repositório, publicado no GitHub Pages. O arquivo não contém dados nem segredos. A chave `anon` embutida é pública por desenho.
- **Banco**: `supabase/schema.sql` (tabelas fechadas por RLS; tudo passa por funções que checam perfil e permissão).

Recursos: login por e-mail, perfis (admin, suporte, leitura), permissão por cliente, log de acesso e de cópia, links compartilhados com validade, limite de aberturas, tempo de visualização e cancelamento imediato.

Publicação: Settings → Pages → Deploy from a branch → `main` / root.
