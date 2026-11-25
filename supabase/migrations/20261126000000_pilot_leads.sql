-- Pilot applications from the landing page form. Anyone can insert; only staff can read or update.
create table if not exists public.pilot_leads (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  name text not null check (char_length(name) between 1 and 120),
  email text not null check (char_length(email) between 3 and 200 and email like '%@%'),
  company text not null check (char_length(company) between 1 and 160),
  product text check (char_length(product) <= 200),
  volume text check (char_length(volume) <= 60),
  message text check (char_length(message) <= 2000),
  status text not null default 'new' check (status in ('new','contacted','pilot','declined'))
);
alter table public.pilot_leads enable row level security;
create policy "anyone can apply" on public.pilot_leads for insert to anon, authenticated with check (status = 'new');
create policy "staff read leads" on public.pilot_leads for select to authenticated using (public.is_staff());
create policy "staff update leads" on public.pilot_leads for update to authenticated using (public.is_staff()) with check (public.is_staff());
grant insert on public.pilot_leads to anon, authenticated;
grant select, update on public.pilot_leads to authenticated;
