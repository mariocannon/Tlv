-- CardForge Pool: credential pools for ICT sites
-- Reads go through RLS; every write goes through a SECURITY DEFINER function that enforces the pool rules.

create schema if not exists private;
grant usage on schema private to authenticated;

-- ------------------------------------------------------------------ tables
create table public.installers (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(trim(name)) between 1 and 120),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create table public.sites (
  id uuid primary key default gen_random_uuid(),
  installer_id uuid not null references public.installers(id) on delete cascade,
  name text not null check (length(trim(name)) between 1 and 120),
  site_code integer not null check (site_code between 0 and 65535),
  format text not null default 'W34' check (format in ('W26', 'W34', 'RAW48')),
  topup_requested boolean not null default false,
  created_at timestamptz not null default now(),
  unique (installer_id, site_code),
  check (format <> 'W26' or site_code <= 255)
);
create index sites_installer_idx on public.sites(installer_id);

create table public.memberships (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  installer_id uuid references public.installers(id) on delete cascade,
  site_id uuid references public.sites(id) on delete cascade,
  role text not null check (role in ('installer', 'owner')),
  created_at timestamptz not null default now(),
  check ((role = 'installer' and installer_id is not null and site_id is null)
      or (role = 'owner' and site_id is not null and installer_id is null)),
  unique nulls not distinct (user_id, installer_id, site_id)
);
create index memberships_user_idx on public.memberships(user_id);
create index memberships_installer_idx on public.memberships(installer_id);
create index memberships_site_idx on public.memberships(site_id);

create table public.owner_invites (
  id uuid primary key default gen_random_uuid(),
  site_id uuid not null references public.sites(id) on delete cascade,
  email text not null check (email = lower(email) and position('@' in email) > 1),
  invited_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  unique (site_id, email)
);
create index owner_invites_email_idx on public.owner_invites(email);
create index owner_invites_invited_by_idx on public.owner_invites(invited_by);

create table public.credentials (
  id uuid primary key default gen_random_uuid(),
  site_id uuid not null references public.sites(id) on delete cascade,
  card_number bigint not null check (card_number between 0 and 4294967295),
  status text not null default 'available' check (status in ('available', 'assigned', 'quarantine', 'retired')),
  carrier text check (carrier in ('phone', 'card')),
  holder_name text,
  holder_email text,
  assigned_at timestamptz,
  expires_on date,
  ready boolean not null default false,
  invite_token text,
  reuse_count integer not null default 0,
  check_panel boolean not null default false,
  check_carrier boolean not null default false,
  retired_reason text,
  freed_at timestamptz,
  updated_at timestamptz not null default now(),
  unique (site_id, card_number)
);
create index credentials_site_status_idx on public.credentials(site_id, status);

create table public.panel_changes (
  id bigint generated always as identity primary key,
  site_id uuid not null references public.sites(id) on delete cascade,
  credential_id uuid references public.credentials(id) on delete set null,
  card_number bigint not null,
  op text not null check (op in ('add', 'remove')),
  holder_name text,
  done boolean not null default false,
  done_at timestamptz,
  done_by uuid references auth.users(id) on delete set null,
  note text,
  created_at timestamptz not null default now()
);
create index panel_changes_site_idx on public.panel_changes(site_id, done);
create index panel_changes_cred_idx on public.panel_changes(credential_id);
create index panel_changes_done_by_idx on public.panel_changes(done_by);

create table public.events (
  id bigint generated always as identity primary key,
  site_id uuid not null references public.sites(id) on delete cascade,
  actor uuid references auth.users(id) on delete set null,
  message text not null,
  created_at timestamptz not null default now()
);
create index events_site_idx on public.events(site_id, created_at desc);
create index events_actor_idx on public.events(actor);
create index installers_created_by_idx on public.installers(created_by);

-- ------------------------------------------------------------------ access helpers (not exposed through the API)
create function private.is_installer_member(p_installer uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.memberships m
    where m.user_id = (select auth.uid()) and m.role = 'installer' and m.installer_id = p_installer);
$$;

create function private.site_role(p_site uuid) returns text
language sql stable security definer set search_path = '' as $$
  select case
    when exists (select 1 from public.sites s
                 join public.memberships m on m.installer_id = s.installer_id and m.role = 'installer'
                 where s.id = p_site and m.user_id = (select auth.uid())) then 'installer'
    when exists (select 1 from public.memberships m
                 where m.site_id = p_site and m.role = 'owner' and m.user_id = (select auth.uid())) then 'owner'
  end;
$$;

create function private.require_site(p_site uuid, p_need text default 'any') returns text
language plpgsql stable security definer set search_path = '' as $$
declare v_role text;
begin
  if (select auth.uid()) is null then raise exception 'Sign in first'; end if;
  v_role := private.site_role(p_site);
  if v_role is null then raise exception 'You don''t have access to that site'; end if;
  if p_need = 'installer' and v_role <> 'installer' then raise exception 'Only the installer can do that'; end if;
  return v_role;
end;
$$;

create function private.log(p_site uuid, p_message text) returns void
language sql security definer set search_path = '' as $$
  insert into public.events (site_id, actor, message) values (p_site, (select auth.uid()), p_message);
$$;

revoke all on all functions in schema private from public, anon;
grant execute on all functions in schema private to authenticated;

-- ------------------------------------------------------------------ RLS (read-only for clients)
alter table public.installers enable row level security;
alter table public.sites enable row level security;
alter table public.memberships enable row level security;
alter table public.owner_invites enable row level security;
alter table public.credentials enable row level security;
alter table public.panel_changes enable row level security;
alter table public.events enable row level security;

create policy "members read installer" on public.installers for select to authenticated
  using (private.is_installer_member(id));
create policy "members read site" on public.sites for select to authenticated
  using (private.site_role(id) is not null);
create policy "read own and managed memberships" on public.memberships for select to authenticated
  using (user_id = (select auth.uid())
         or (installer_id is not null and private.is_installer_member(installer_id))
         or (site_id is not null and private.site_role(site_id) = 'installer'));
create policy "installer reads invites" on public.owner_invites for select to authenticated
  using (private.site_role(site_id) = 'installer');
create policy "members read credentials" on public.credentials for select to authenticated
  using (private.site_role(site_id) is not null);
create policy "members read panel changes" on public.panel_changes for select to authenticated
  using (private.site_role(site_id) is not null);
create policy "members read events" on public.events for select to authenticated
  using (private.site_role(site_id) is not null);

revoke all on public.installers, public.sites, public.memberships, public.owner_invites,
  public.credentials, public.panel_changes, public.events from anon;
revoke insert, update, delete, truncate on public.installers, public.sites, public.memberships, public.owner_invites,
  public.credentials, public.panel_changes, public.events from authenticated;
grant select on public.installers, public.sites, public.memberships, public.owner_invites,
  public.credentials, public.panel_changes, public.events to authenticated;

create view public.site_stats with (security_invoker = true) as
select s.id as site_id,
       count(c.id) as total,
       count(c.id) filter (where c.status = 'available') as available,
       count(c.id) filter (where c.status = 'assigned') as assigned,
       count(c.id) filter (where c.status = 'quarantine') as quarantine,
       count(c.id) filter (where c.status = 'retired') as retired,
       min(c.card_number) as min_card,
       max(c.card_number) as max_card,
       (select count(*) from public.panel_changes p where p.site_id = s.id and not p.done) as pending_changes
from public.sites s
left join public.credentials c on c.site_id = s.id
group by s.id;
revoke all on public.site_stats from anon;
grant select on public.site_stats to authenticated;
