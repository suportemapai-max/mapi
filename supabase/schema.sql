-- =====================================================================
-- Cofre de Acessos MAP — esquema Supabase
-- Cole este arquivo inteiro em: Supabase > SQL Editor > New query > Run
-- Pode ser executado de novo sem problemas (é idempotente).
--
-- Modelo de segurança
--  * Os dados dos registros chegam criptografados do navegador (AES-GCM,
--    chave derivada da "chave do cofre"). O banco guarda só texto cifrado
--    (coluna blob) e o nome/categoria do registro.
--  * As tabelas ficam fechadas (RLS ligada, sem políticas): nenhum acesso
--    direto. Tudo passa pelas funções abaixo, que checam papel e permissão.
--  * Todo evento relevante cai na tabela logs.
-- =====================================================================

create extension if not exists pgcrypto;

-- ---------- tabelas ----------
create table if not exists public.perfis (
  id            uuid primary key references auth.users(id) on delete cascade,
  email         text not null,
  nome          text,
  papel         text not null default 'leitura' check (papel in ('admin','suporte','leitura')),
  ativo         boolean not null default false,
  acesso_total  boolean not null default false,
  criado_em     timestamptz not null default now()
);

create table if not exists public.cofre_config (
  id          int primary key default 1 check (id = 1),
  chave       text not null,   -- chave AES-256 (base64). Só sai pela função obter_chave_cofre(), com Authenticator (aal2)
  criado_em   timestamptz not null default now()
);

create table if not exists public.registros (
  id            text primary key,
  cat           text not null,
  titulo        text not null,
  blob          jsonb not null,
  criado_por    uuid references auth.users(id) on delete set null,
  atualizado_por uuid references auth.users(id) on delete set null,
  atualizado_em timestamptz not null default now()
);

create table if not exists public.permissoes (
  usuario_id  uuid not null references public.perfis(id) on delete cascade,
  registro_id text not null references public.registros(id) on delete cascade,
  primary key (usuario_id, registro_id)
);

create table if not exists public.logs (
  id              bigserial primary key,
  ts              timestamptz not null default now(),
  usuario_id      uuid,
  email           text,
  tipo            text not null,
  registro_id     text,
  registro_titulo text,
  campo           text,
  detalhe         text,
  link_id         uuid
);
create index if not exists logs_ts_idx on public.logs (ts desc);
create index if not exists logs_tipo_idx on public.logs (tipo);

create table if not exists public.links (
  id                uuid primary key default gen_random_uuid(),
  registro_id       text references public.registros(id) on delete cascade,
  titulo            text not null,
  blob              jsonb not null,
  criado_por        uuid references auth.users(id) on delete set null,
  criado_por_email  text,
  criado_em         timestamptz not null default now(),
  expira_em         timestamptz not null,
  max_views         int,
  views             int not null default 0,
  visualizacao_seg  int not null default 120,
  revogado_em       timestamptz
);

alter table public.perfis       enable row level security;
alter table public.cofre_config enable row level security;
alter table public.registros    enable row level security;
alter table public.permissoes   enable row level security;
alter table public.logs         enable row level security;
alter table public.links        enable row level security;
-- (sem políticas de propósito: acesso direto negado; só as funções abaixo)

revoke all on public.perfis, public.cofre_config, public.registros,
              public.permissoes, public.logs, public.links from anon, authenticated;
revoke all on sequence public.logs_id_seq from anon, authenticated;

-- ---------- novo usuário: perfil automático ----------
-- O primeiro usuário que se cadastrar vira admin ativo. Os demais entram
-- inativos (leitura) e esperam aprovação do admin.
create or replace function public.tg_novo_usuario() returns trigger
language plpgsql security definer set search_path = public as $$
declare primeiro boolean;
begin
  select not exists (select 1 from public.perfis) into primeiro;
  insert into public.perfis (id, email, nome, papel, ativo, acesso_total)
  values (new.id, new.email, coalesce(new.raw_user_meta_data->>'nome', split_part(new.email,'@',1)),
          case when primeiro then 'admin' else 'leitura' end, primeiro, primeiro)
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.tg_novo_usuario();

-- ---------- auxiliares (não expostas) ----------
create or replace function public._perfil_basico() returns public.perfis
language plpgsql stable security definer set search_path = public as $$
declare v public.perfis;
begin
  select * into v from public.perfis where id = auth.uid() and ativo;
  if v.id is null then raise exception 'sem_acesso' using errcode = '42501'; end if;
  return v;
end $$;

-- Exige sessão com Authenticator confirmado (aal2) para tudo que toca dados.
create or replace function public._perfil_ativo() returns public.perfis
language plpgsql stable security definer set search_path = public as $$
declare v public.perfis;
begin
  v := public._perfil_basico();
  if coalesce(auth.jwt() ->> 'aal', '') <> 'aal2' then raise exception 'mfa_requerido' using errcode = '42501'; end if;
  return v;
end $$;

create or replace function public._pode_ver(p public.perfis, reg text) returns boolean
language sql stable security definer set search_path = public as $$
  select p.papel = 'admin' or p.acesso_total
      or exists (select 1 from public.permissoes x where x.usuario_id = p.id and x.registro_id = reg)
$$;

create or replace function public._log(p_uid uuid, p_email text, p_tipo text, p_reg text,
                                       p_campo text, p_detalhe text, p_link uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  insert into public.logs (usuario_id, email, tipo, registro_id, registro_titulo, campo, detalhe, link_id)
  values (p_uid, p_email, p_tipo, p_reg,
          (select titulo from public.registros where id = p_reg), left(p_campo, 200), left(p_detalhe, 500), p_link);
end $$;

revoke all on function public._perfil_basico(), public._perfil_ativo(), public._pode_ver(public.perfis, text),
  public._log(uuid, text, text, text, text, text, uuid), public.tg_novo_usuario() from public, anon, authenticated;

-- ---------- sessão / configuração ----------
create or replace function public.meu_perfil() returns jsonb
language sql stable security definer set search_path = public as $$
  select to_jsonb(p) - 'criado_em' from public.perfis p where p.id = auth.uid()
$$;

create or replace function public.cofre_configurado() returns boolean
language plpgsql stable security definer set search_path = public as $$
begin
  perform public._perfil_basico();
  return exists (select 1 from public.cofre_config);
end $$;

create or replace function public.configurar_cofre(p_chave text) returns void
language plpgsql security definer set search_path = public as $$
declare p public.perfis;
begin
  p := public._perfil_ativo();
  if p.papel <> 'admin' then raise exception 'somente_admin' using errcode = '42501'; end if;
  if exists (select 1 from public.cofre_config) then raise exception 'ja_configurado'; end if;
  if length(p_chave) < 40 then raise exception 'chave_invalida'; end if;
  insert into public.cofre_config (id, chave) values (1, p_chave);
  perform public._log(p.id, p.email, 'cofre_configurado', null, null, null, null);
end $$;

create or replace function public.obter_chave_cofre() returns text
language plpgsql security definer set search_path = public as $$
declare p public.perfis; k text;
begin
  p := public._perfil_ativo();
  select chave into k from public.cofre_config where id = 1;
  if k is null then raise exception 'cofre_nao_configurado'; end if;
  perform public._log(p.id, p.email, 'cofre_aberto', null, null, null, null);
  return k;
end $$;

-- ---------- registros ----------
create or replace function public.carregar_registros()
returns table (id text, cat text, titulo text, blob jsonb, atualizado_em timestamptz)
language plpgsql security definer set search_path = public as $$
declare p public.perfis;
begin
  p := public._perfil_ativo();
  perform public._log(p.id, p.email, 'carregar', null, null, null, null);
  return query
    select r.id, r.cat, r.titulo, r.blob, r.atualizado_em from public.registros r
    where public._pode_ver(p, r.id) order by r.titulo;
end $$;

create or replace function public.salvar_registro(p_id text, p_cat text, p_titulo text, p_blob jsonb) returns void
language plpgsql security definer set search_path = public as $$
declare p public.perfis; existe boolean;
begin
  p := public._perfil_ativo();
  if p.papel not in ('admin','suporte') then raise exception 'sem_permissao_escrita' using errcode = '42501'; end if;
  select exists (select 1 from public.registros where id = p_id) into existe;
  if existe and not public._pode_ver(p, p_id) then raise exception 'sem_permissao_registro' using errcode = '42501'; end if;
  insert into public.registros (id, cat, titulo, blob, criado_por, atualizado_por, atualizado_em)
  values (p_id, p_cat, p_titulo, p_blob, p.id, p.id, now())
  on conflict (id) do update set cat = excluded.cat, titulo = excluded.titulo, blob = excluded.blob,
    atualizado_por = p.id, atualizado_em = now();
  if not existe and p.papel <> 'admin' and not p.acesso_total then
    insert into public.permissoes (usuario_id, registro_id) values (p.id, p_id) on conflict do nothing;
  end if;
  perform public._log(p.id, p.email, case when existe then 'editar' else 'criar' end, p_id, null, null, null);
end $$;

create or replace function public.importar_registros(p_itens jsonb) returns int
language plpgsql security definer set search_path = public as $$
declare p public.perfis; i jsonb; n int := 0;
begin
  p := public._perfil_ativo();
  if p.papel <> 'admin' then raise exception 'somente_admin' using errcode = '42501'; end if;
  for i in select * from jsonb_array_elements(p_itens) loop
    insert into public.registros (id, cat, titulo, blob, criado_por, atualizado_por)
    values (i->>'id', i->>'cat', i->>'titulo', i->'blob', p.id, p.id)
    on conflict (id) do update set cat = excluded.cat, titulo = excluded.titulo, blob = excluded.blob,
      atualizado_por = p.id, atualizado_em = now();
    n := n + 1;
  end loop;
  perform public._log(p.id, p.email, 'importar', null, null, n || ' registros', null);
  return n;
end $$;

create or replace function public.excluir_registro(p_id text) returns void
language plpgsql security definer set search_path = public as $$
declare p public.perfis;
begin
  p := public._perfil_ativo();
  if p.papel <> 'admin' then raise exception 'somente_admin' using errcode = '42501'; end if;
  perform public._log(p.id, p.email, 'excluir', p_id, null, null, null);
  delete from public.registros where id = p_id;
end $$;

-- ---------- log ----------
create or replace function public.registrar_evento(p_tipo text, p_registro text default null,
                                                   p_campo text default null, p_detalhe text default null) returns void
language plpgsql security definer set search_path = public as $$
declare p public.perfis;
begin
  p := public._perfil_ativo();
  if p_tipo not in ('login','logout','abrir','revelar','copiar','exportar','bloqueio') then
    raise exception 'tipo_invalido';
  end if;
  if p_registro is not null and not public._pode_ver(p, p_registro) then
    raise exception 'sem_permissao_registro' using errcode = '42501';
  end if;
  perform public._log(p.id, p.email, p_tipo, p_registro, p_campo, p_detalhe, null);
end $$;

create or replace function public.listar_logs(p_limite int default 300, p_tipo text default null, p_busca text default null)
returns setof public.logs
language plpgsql security definer set search_path = public as $$
declare p public.perfis;
begin
  p := public._perfil_ativo();
  if p.papel <> 'admin' then raise exception 'somente_admin' using errcode = '42501'; end if;
  return query
    select * from public.logs l
    where (p_tipo is null or p_tipo = '' or l.tipo = p_tipo)
      and (p_busca is null or p_busca = '' or
           (coalesce(l.email,'') || ' ' || coalesce(l.registro_titulo,'') || ' ' || coalesce(l.campo,'') || ' ' || coalesce(l.detalhe,'')) ilike '%' || p_busca || '%')
    order by l.ts desc limit least(greatest(p_limite, 1), 2000);
end $$;

-- ---------- usuários e permissões ----------
create or replace function public.listar_usuarios() returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare p public.perfis;
begin
  p := public._perfil_ativo();
  if p.papel <> 'admin' then raise exception 'somente_admin' using errcode = '42501'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object(
      'id', u.id, 'email', u.email, 'nome', u.nome, 'papel', u.papel, 'ativo', u.ativo,
      'acesso_total', u.acesso_total, 'criado_em', u.criado_em,
      'registros', coalesce((select jsonb_agg(x.registro_id) from public.permissoes x where x.usuario_id = u.id), '[]'::jsonb))
      order by u.ativo, u.email) from public.perfis u), '[]'::jsonb);
end $$;

create or replace function public.atualizar_usuario(p_id uuid, p_papel text, p_ativo boolean,
                                                    p_total boolean, p_registros text[]) returns void
language plpgsql security definer set search_path = public as $$
declare p public.perfis; alvo public.perfis;
begin
  p := public._perfil_ativo();
  if p.papel <> 'admin' then raise exception 'somente_admin' using errcode = '42501'; end if;
  if p_papel not in ('admin','suporte','leitura') then raise exception 'papel_invalido'; end if;
  select * into alvo from public.perfis where id = p_id;
  if alvo.id is null then raise exception 'usuario_inexistente'; end if;
  if p_id = p.id and (p_papel <> 'admin' or not p_ativo) then
    raise exception 'nao_pode_rebaixar_a_si_mesmo';
  end if;
  update public.perfis set papel = p_papel, ativo = p_ativo, acesso_total = p_total where id = p_id;
  delete from public.permissoes where usuario_id = p_id;
  if not p_total and p_papel <> 'admin' then
    insert into public.permissoes (usuario_id, registro_id)
      select p_id, r.id from public.registros r where r.id = any(p_registros);
  end if;
  perform public._log(p.id, p.email, 'permissao', null, alvo.email,
                      p_papel || case when p_ativo then ', ativo' else ', inativo' end
                      || case when p_total then ', acesso total' else ', ' || coalesce(array_length(p_registros,1),0) || ' registros' end, null);
end $$;

-- ---------- links compartilhados ----------
create or replace function public.criar_link(p_registro text, p_blob jsonb, p_expira timestamptz,
                                             p_max int, p_visualizacao int) returns uuid
language plpgsql security definer set search_path = public as $$
declare p public.perfis; novo uuid;
begin
  p := public._perfil_ativo();
  if p.papel not in ('admin','suporte') then raise exception 'sem_permissao_escrita' using errcode = '42501'; end if;
  if not public._pode_ver(p, p_registro) then raise exception 'sem_permissao_registro' using errcode = '42501'; end if;
  if p_expira <= now() or p_expira > now() + interval '30 days' then raise exception 'expiracao_invalida'; end if;
  insert into public.links (registro_id, titulo, blob, criado_por, criado_por_email, expira_em, max_views, visualizacao_seg)
  values (p_registro, (select titulo from public.registros where id = p_registro), p_blob, p.id, p.email,
          p_expira, nullif(p_max, 0), least(greatest(p_visualizacao, 15), 1800))
  returning id into novo;
  perform public._log(p.id, p.email, 'link_criado', p_registro, null,
                      'expira ' || to_char(p_expira at time zone 'America/Manaus', 'DD/MM HH24:MI')
                      || ', ' || coalesce(nullif(p_max,0)::text, 'sem limite de') || ' aberturas', novo);
  return novo;
end $$;

create or replace function public.listar_links(p_registro text default null) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare p public.perfis;
begin
  p := public._perfil_ativo();
  return coalesce((select jsonb_agg(jsonb_build_object(
      'id', l.id, 'registro_id', l.registro_id, 'titulo', l.titulo, 'criado_por', l.criado_por_email,
      'criado_em', l.criado_em, 'expira_em', l.expira_em, 'max_views', l.max_views, 'views', l.views,
      'visualizacao_seg', l.visualizacao_seg, 'revogado_em', l.revogado_em,
      'status', case when l.revogado_em is not null then 'revogado'
                     when l.expira_em <= now() then 'expirado'
                     when l.max_views is not null and l.views >= l.max_views then 'esgotado'
                     else 'ativo' end) order by l.criado_em desc)
    from public.links l
    where (p.papel = 'admin' or l.criado_por = p.id)
      and (p_registro is null or l.registro_id = p_registro)), '[]'::jsonb);
end $$;

create or replace function public.revogar_link(p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
declare p public.perfis; l public.links;
begin
  p := public._perfil_ativo();
  select * into l from public.links where id = p_id;
  if l.id is null or (p.papel <> 'admin' and l.criado_por is distinct from p.id) then
    raise exception 'link_inexistente';
  end if;
  update public.links set revogado_em = coalesce(revogado_em, now()), blob = '{}'::jsonb where id = p_id;
  perform public._log(p.id, p.email, 'link_revogado', l.registro_id, null, null, p_id);
end $$;

-- Funções públicas (visitante sem login, só com o ID do link)
create or replace function public.abrir_link(p_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare l public.links;
begin
  select * into l from public.links where id = p_id for update;
  if l.id is null or l.revogado_em is not null or l.expira_em <= now()
     or (l.max_views is not null and l.views >= l.max_views) then
    raise exception 'link_invalido';
  end if;
  update public.links set views = views + 1 where id = p_id;
  perform public._log(null, 'visitante (link)', 'link_aberto', l.registro_id, null,
                      'abertura ' || (l.views + 1) || coalesce(' de ' || l.max_views, ''), p_id);
  return jsonb_build_object('titulo', l.titulo, 'blob', l.blob, 'expira_em', l.expira_em,
                            'visualizacao_seg', l.visualizacao_seg, 'views', l.views + 1, 'max_views', l.max_views);
end $$;

create or replace function public.status_link(p_id uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.links l where l.id = p_id and l.revogado_em is null and l.expira_em > now())
$$;

create or replace function public.registrar_evento_link(p_id uuid, p_campo text default null) returns void
language plpgsql security definer set search_path = public as $$
declare l public.links;
begin
  select * into l from public.links where id = p_id and revogado_em is null and expira_em > now();
  if l.id is null then return; end if;
  perform public._log(null, 'visitante (link)', 'link_copiou', l.registro_id, p_campo, null, p_id);
end $$;

-- ---------- permissões de execução ----------
revoke all on function
  public.meu_perfil(), public.cofre_configurado(), public.configurar_cofre(text), public.obter_chave_cofre(),
  public.carregar_registros(), public.salvar_registro(text, text, text, jsonb),
  public.importar_registros(jsonb), public.excluir_registro(text),
  public.registrar_evento(text, text, text, text), public.listar_logs(int, text, text),
  public.listar_usuarios(), public.atualizar_usuario(uuid, text, boolean, boolean, text[]),
  public.criar_link(text, jsonb, timestamptz, int, int), public.listar_links(text),
  public.revogar_link(uuid), public.abrir_link(uuid), public.status_link(uuid),
  public.registrar_evento_link(uuid, text)
from public, anon, authenticated;

grant execute on function
  public.meu_perfil(), public.cofre_configurado(), public.configurar_cofre(text), public.obter_chave_cofre(),
  public.carregar_registros(), public.salvar_registro(text, text, text, jsonb),
  public.importar_registros(jsonb), public.excluir_registro(text),
  public.registrar_evento(text, text, text, text), public.listar_logs(int, text, text),
  public.listar_usuarios(), public.atualizar_usuario(uuid, text, boolean, boolean, text[]),
  public.criar_link(text, jsonb, timestamptz, int, int), public.listar_links(text),
  public.revogar_link(uuid)
to authenticated;

grant execute on function
  public.abrir_link(uuid), public.status_link(uuid), public.registrar_evento_link(uuid, text)
to anon, authenticated;
