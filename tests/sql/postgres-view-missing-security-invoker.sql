-- Fixtures for the Postgres view / SECURITY DEFINER rules.
--
-- Note on the annotation style: Semgrep's test harness recognises `#`, `/``/`,
-- `<!--` and `(*` as comment openers, but not SQL's double dash. Each annotation
-- below is therefore a double-dash SQL comment that carries a slash-slash opener
-- inside it, which keeps the file valid SQL while the harness still parses it.
--
-- The tables below have RLS enabled with a per-tenant policy. Everything that
-- follows is about whether a caller reaching the object through PostgREST gets
-- those policies applied or not.

create table public.profiles (
  id uuid primary key,
  tenant_id uuid not null,
  email text not null,
  billing_customer_id text
);

alter table public.profiles enable row level security;

create policy tenant_isolation on public.profiles
  for select using (tenant_id = auth.jwt() ->> 'tenant_id');

-- The view is owned by the migration role, which is RLS-exempt, so this returns
-- every tenant's rows to every caller.
-- // ruleid: postgres-view-missing-security-invoker
CREATE VIEW public.profile_directory AS
  SELECT id, tenant_id, email FROM public.profiles;

-- CREATE OR REPLACE does not carry forward options that are not restated, so a
-- later migration can silently drop security_invoker from a view that had it.
-- // ruleid: postgres-view-missing-security-invoker
create or replace view public.billing_overview as
  select p.id, p.email, p.billing_customer_id
  from public.profiles p;

-- // ok: postgres-view-missing-security-invoker
CREATE VIEW public.profile_directory_safe
  WITH (security_invoker = on) AS
  SELECT id, tenant_id, email FROM public.profiles;

-- // ok: postgres-view-missing-security-invoker
create or replace view public.billing_overview_safe
  with (security_invoker = true, security_barrier = true) as
  select p.id, p.email, p.billing_customer_id
  from public.profiles p;

-- A materialized view cannot have security_invoker at all; it is a stored
-- snapshot and has to be protected by not exposing it.
-- // ok: postgres-view-missing-security-invoker
-- // ok: postgres-security-definer-function-in-public-schema
create table internal.profile_snapshot as
  select id, email from public.profiles;

-- Reachable over PostgREST as POST /rpc/promote_user, running as the owner.
-- // ruleid: postgres-security-definer-function-in-public-schema
CREATE OR REPLACE FUNCTION public.promote_user(target uuid)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
  UPDATE public.profiles SET email = email WHERE id = target;
$$;

-- Unqualified, so it is created in the first schema on the search path.
-- // ruleid: postgres-security-definer-function-in-public-schema
create function delete_account(target uuid)
returns void
language plpgsql
security definer
as $$
begin
  delete from public.profiles where id = target;
end;
$$;

-- Invoker rights: the caller's policies apply, so this is the safe default.
-- // ok: postgres-security-definer-function-in-public-schema
create or replace function public.my_profile()
returns setof public.profiles
language sql
stable
as $$
  select * from public.profiles;
$$;

-- Definer rights, but in a schema that is not exposed over the REST API.
-- // ok: postgres-security-definer-function-in-public-schema
create or replace function private.rotate_api_key(target uuid)
returns text
language plpgsql
security definer
set search_path = ''
as $$
begin
  return encode(public.gen_random_bytes(32), 'hex');
end;
$$;
