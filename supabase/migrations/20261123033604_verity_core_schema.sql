-- Verity MVP core schema (as applied to the Verity Supabase project, plus the lock-down migration below).

create table public.staff (
  user_id uuid primary key references auth.users on delete cascade,
  created_at timestamptz not null default now()
);

create or replace function public.is_staff() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.staff where user_id = auth.uid());
$$;

-- First account ever created becomes staff (the owner). Everyone after needs adding by hand.
create or replace function public.claim_first_staff() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.staff) then
    insert into public.staff (user_id) values (new.id);
  end if;
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.claim_first_staff();

create table public.brands (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null check (slug ~ '^[a-z0-9-]{2,32}$'),
  name text not null,
  accent text not null default '#0E6B59',
  story text,
  link_label text,
  link_url text,
  key_secret_id uuid,            -- vault.secrets id holding this brand's master keys
  created_at timestamptz not null default now()
);

create table public.products (
  id uuid primary key default gen_random_uuid(),
  brand_id uuid not null references public.brands on delete cascade,
  name text not null,
  details text,
  created_at timestamptz not null default now()
);

create table public.batches (
  id uuid primary key default gen_random_uuid(),
  brand_id uuid not null references public.brands on delete cascade,
  product_id uuid not null references public.products on delete cascade,
  code text not null,
  tag_type text not null default 'NTAG 424 DNA sticker',
  planned_qty int not null default 10,
  created_at timestamptz not null default now(),
  unique (brand_id, code)
);

create table public.tags (
  id uuid primary key default gen_random_uuid(),
  brand_id uuid not null references public.brands on delete cascade,
  batch_id uuid not null references public.batches on delete cascade,
  uid text not null check (uid ~ '^[0-9A-F]{14}$'),
  status text not null default 'active' check (status in ('active','cancelled','reset')),
  last_ctr int not null default -1,
  scan_count int not null default 0,
  first_scan_at timestamptz,
  last_scan_at timestamptz,
  encoded_at timestamptz not null default now(),
  encoded_by uuid references auth.users,
  unique (brand_id, uid)
);

create table public.scans (
  id bigserial primary key,
  brand_id uuid not null references public.brands on delete cascade,
  tag_id uuid references public.tags on delete set null,
  product_id uuid references public.products on delete set null,
  uid text,
  ctr int,
  verdict text not null,
  source text not null default 'shopper' check (source in ('shopper','qc')),
  place text,
  user_agent text,
  created_at timestamptz not null default now()
);
create index scans_brand_time on public.scans (brand_id, created_at desc);
create index scans_tag_time on public.scans (tag_id, created_at desc);

create table public.alerts (
  id uuid primary key default gen_random_uuid(),
  brand_id uuid not null references public.brands on delete cascade,
  tag_id uuid references public.tags on delete set null,
  scan_id bigint references public.scans on delete set null,
  rule text not null,
  severity text not null check (severity in ('high','medium','low')),
  message text not null,
  status text not null default 'open' check (status in ('open','resolved')),
  created_at timestamptz not null default now()
);

-- RLS: staff can see and manage everything (the MVP is operated by Verity staff only).
alter table public.staff enable row level security;
alter table public.brands enable row level security;
alter table public.products enable row level security;
alter table public.batches enable row level security;
alter table public.tags enable row level security;
alter table public.scans enable row level security;
alter table public.alerts enable row level security;

create policy staff_read_self on public.staff for select to authenticated using (user_id = auth.uid());
create policy staff_all_brands on public.brands for all to authenticated using (public.is_staff()) with check (public.is_staff());
create policy staff_all_products on public.products for all to authenticated using (public.is_staff()) with check (public.is_staff());
create policy staff_all_batches on public.batches for all to authenticated using (public.is_staff()) with check (public.is_staff());
create policy staff_all_tags on public.tags for all to authenticated using (public.is_staff()) with check (public.is_staff());
create policy staff_read_scans on public.scans for select to authenticated using (public.is_staff());
create policy staff_all_alerts on public.alerts for all to authenticated using (public.is_staff()) with check (public.is_staff());

-- Brand master keys live in Supabase Vault (encrypted at rest). Only the service role can read them.
create or replace function public.get_brand_keys(p_brand_id uuid) returns json
language sql stable security definer set search_path = public, vault as $$
  select s.decrypted_secret::json
  from public.brands b join vault.decrypted_secrets s on s.id = b.key_secret_id
  where b.id = p_brand_id;
$$;
revoke all on function public.get_brand_keys(uuid) from public, anon, authenticated;
grant execute on function public.get_brand_keys(uuid) to service_role;

create or replace function public.create_brand_keys_internal(p_brand_id uuid) returns void
language plpgsql security definer set search_path = public, vault, extensions as $$
declare sid uuid; keys text;
begin
  keys := json_build_object(
    'meta', encode(extensions.gen_random_bytes(16), 'hex'),
    'mac',  encode(extensions.gen_random_bytes(16), 'hex'),
    'cfg',  encode(extensions.gen_random_bytes(16), 'hex'))::text;
  sid := vault.create_secret(keys, 'verity-brand-' || p_brand_id::text, 'Verity brand master keys');
  update public.brands set key_secret_id = sid where id = p_brand_id;
end $$;
revoke all on function public.create_brand_keys_internal(uuid) from public, anon, authenticated;

-- Give every new brand its keys automatically.
create or replace function public.brand_keys_trigger() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  perform public.create_brand_keys_internal(new.id);
  return new;
end $$;
create trigger brands_create_keys after insert on public.brands
  for each row execute function public.brand_keys_trigger();

-- Atomic counter check: only succeeds if the new counter is higher than the last accepted one.
create or replace function public.accept_counter(p_tag_id uuid, p_ctr int, p_count boolean) returns boolean
language plpgsql security definer set search_path = public as $$
declare n int;
begin
  update public.tags
     set last_ctr = p_ctr,
         scan_count = scan_count + case when p_count then 1 else 0 end,
         first_scan_at = case when p_count then coalesce(first_scan_at, now()) else first_scan_at end,
         last_scan_at = now()
   where id = p_tag_id and last_ctr < p_ctr;
  get diagnostics n = row_count;
  return n = 1;
end $$;
revoke all on function public.accept_counter(uuid, int, boolean) from public, anon, authenticated;
grant execute on function public.accept_counter(uuid, int, boolean) to service_role;

-- Lock-down (applied as migration lock_down_functions)
revoke all on function public.brand_keys_trigger() from public, anon, authenticated;
revoke all on function public.claim_first_staff() from public, anon, authenticated;
revoke all on function public.is_staff() from public, anon;
grant execute on function public.is_staff() to authenticated;
