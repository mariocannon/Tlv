-- CardForge Pool: all writes. Each function checks the caller's role and enforces the credential lifecycle:
--   available -> assigned -> quarantine -> (panel removed + carrier wiped) -> available (reuse_count + 1)
--   assigned -> retired (lost/stolen, never reused)

create or replace function public.create_installer(p_name text) returns uuid
language plpgsql security definer set search_path = '' as $$
declare v_id uuid; v_uid uuid := (select auth.uid());
begin
  if v_uid is null then raise exception 'Sign in first'; end if;
  if exists (select 1 from public.memberships where user_id = v_uid and role = 'installer') then
    raise exception 'You already have an installer account';
  end if;
  if length(trim(coalesce(p_name, ''))) = 0 then raise exception 'Enter a business name'; end if;
  insert into public.installers (name, created_by) values (trim(p_name), v_uid) returning id into v_id;
  insert into public.memberships (user_id, installer_id, role) values (v_uid, v_id, 'installer');
  return v_id;
end;
$$;

create or replace function private.max_card(p_format text) returns bigint
language sql immutable set search_path = '' as $$
  select case when p_format = 'RAW48' then 4294967295 else 65535 end::bigint;
$$;

create or replace function public.create_site(p_installer uuid, p_name text, p_site_code integer,
                                              p_format text default 'W34', p_pool_size integer default 20) returns uuid
language plpgsql security definer set search_path = '' as $$
declare v_id uuid;
begin
  if not private.is_installer_member(p_installer) then raise exception 'Only the installer can add sites'; end if;
  if length(trim(coalesce(p_name, ''))) = 0 then raise exception 'Enter a site name'; end if;
  if p_format not in ('W26', 'W34', 'RAW48') then raise exception 'Unknown card format'; end if;
  if p_site_code is null or p_site_code < 0 or p_site_code > 65535 then raise exception 'Site code must be 0-65535'; end if;
  if p_format = 'W26' and p_site_code > 255 then raise exception '26-bit format only allows site codes up to 255'; end if;
  if p_pool_size is null or p_pool_size < 1 or p_pool_size > 1000 then raise exception 'Pool size must be 1-1000'; end if;
  if exists (select 1 from public.sites where installer_id = p_installer and site_code = p_site_code) then
    raise exception 'Site code % is already used by another of your sites', p_site_code;
  end if;
  insert into public.sites (installer_id, name, site_code, format)
    values (p_installer, trim(p_name), p_site_code, p_format) returning id into v_id;
  insert into public.credentials (site_id, card_number)
    select v_id, g from generate_series(1001, 1000 + p_pool_size) g;
  perform private.log(v_id, format('Site created with %s credentials (%s/%s-%s).', p_pool_size, p_site_code, 1001, 1000 + p_pool_size));
  return v_id;
end;
$$;

create or replace function public.topup_pool(p_site uuid, p_count integer) returns bigint
language plpgsql security definer set search_path = '' as $$
declare v_from bigint; v_site public.sites;
begin
  perform private.require_site(p_site, 'installer');
  if p_count is null or p_count < 1 or p_count > 1000 then raise exception 'Top up 1-1000 credentials at a time'; end if;
  select * into v_site from public.sites where id = p_site for update;
  select coalesce(max(card_number), 1000) + 1 into v_from from public.credentials where site_id = p_site;
  if v_from + p_count - 1 > private.max_card(v_site.format) then
    raise exception 'That would go past the highest card number for this format';
  end if;
  insert into public.credentials (site_id, card_number)
    select p_site, g from generate_series(v_from, v_from + p_count - 1) g;
  update public.sites set topup_requested = false where id = p_site;
  perform private.log(p_site, format('Pool topped up with %s credentials (%s/%s-%s).', p_count, v_site.site_code, v_from, v_from + p_count - 1));
  return v_from;
end;
$$;

create or replace function public.request_topup(p_site uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  perform private.require_site(p_site);
  update public.sites set topup_requested = true where id = p_site;
  perform private.log(p_site, 'More credentials requested for this site.');
end;
$$;

create or replace function public.assign_credential(p_site uuid, p_name text, p_email text, p_carrier text,
                                                    p_expires date default null, p_card bigint default null)
returns public.credentials
language plpgsql security definer set search_path = '' as $$
declare v public.credentials;
begin
  perform private.require_site(p_site);
  if length(trim(coalesce(p_name, ''))) = 0 then raise exception 'Enter the person''s name'; end if;
  if p_email is null or position('@' in p_email) < 2 then raise exception 'Enter a valid email'; end if;
  if p_carrier not in ('phone', 'card') then raise exception 'Choose phone or card'; end if;
  if p_expires is not null and p_expires < current_date then raise exception 'Expiry date is in the past'; end if;

  select * into v from public.credentials
   where site_id = p_site and status = 'available' and (p_card is null or card_number = p_card)
   order by reuse_count, card_number
   limit 1 for update skip locked;
  if not found then
    raise exception '%', case when p_card is null then 'No credentials left in the pool' else 'That credential isn''t available' end;
  end if;

  update public.credentials set
    status = 'assigned', carrier = p_carrier, holder_name = trim(p_name), holder_email = lower(trim(p_email)),
    assigned_at = now(), expires_on = p_expires, ready = false,
    invite_token = replace(gen_random_uuid()::text, '-', ''),
    check_panel = false, check_carrier = false, retired_reason = null, freed_at = null, updated_at = now()
  where id = v.id returning * into v;

  insert into public.panel_changes (site_id, credential_id, card_number, op, holder_name)
    values (p_site, v.id, v.card_number, 'add', v.holder_name);
  perform private.log(p_site, format('Card %s assigned to %s (%s).', v.card_number, v.holder_name,
                                     case when p_carrier = 'phone' then 'phone' else 'card or fob' end));
  return v;
end;
$$;

create or replace function public.mark_ready(p_credential uuid) returns void
language plpgsql security definer set search_path = '' as $$
declare v public.credentials;
begin
  select * into v from public.credentials where id = p_credential for update;
  if not found then raise exception 'Credential not found'; end if;
  perform private.require_site(v.site_id);
  if v.status <> 'assigned' then raise exception 'Only assigned credentials can be marked live'; end if;
  update public.credentials set ready = true, updated_at = now() where id = p_credential;
  perform private.log(v.site_id, format('Card %s %s.', v.card_number,
    case when v.carrier = 'phone' then 'set up on ' || v.holder_name || '''s phone' else 'encoded and handed to ' || v.holder_name end));
end;
$$;

create or replace function public.unassign_credential(p_credential uuid, p_reason text) returns public.credentials
language plpgsql security definer set search_path = '' as $$
declare v public.credentials; v_pending_add bigint; v_panel_clean boolean;
begin
  select * into v from public.credentials where id = p_credential for update;
  if not found then raise exception 'Credential not found'; end if;
  perform private.require_site(v.site_id);
  if v.status <> 'assigned' then raise exception 'Only assigned credentials can be unassigned'; end if;
  if p_reason not in ('returned', 'lost') then raise exception 'Reason must be returned or lost'; end if;

  -- If the panel was never updated for this person, cancel that step instead of adding a removal.
  select id into v_pending_add from public.panel_changes
   where credential_id = v.id and op = 'add' and not done order by id desc limit 1;
  if v_pending_add is not null then
    update public.panel_changes set done = true, done_at = now(), done_by = (select auth.uid()),
      note = 'Cancelled: unassigned before it was added to the panel' where id = v_pending_add;
    v_panel_clean := true;
  else
    insert into public.panel_changes (site_id, credential_id, card_number, op, holder_name)
      values (v.site_id, v.id, v.card_number, 'remove', v.holder_name);
    v_panel_clean := false;
  end if;

  if p_reason = 'lost' then
    update public.credentials set status = 'retired', freed_at = now(), updated_at = now(), invite_token = null,
      retired_reason = case when v.carrier = 'phone' then 'Phone lost' else 'Lost or stolen' end
    where id = v.id returning * into v;
    perform private.log(v.site_id, format('Card %s (%s) reported lost or stolen. Retired permanently.', v.card_number, v.holder_name));
  else
    update public.credentials set status = 'quarantine', freed_at = now(), updated_at = now(), invite_token = null,
      check_panel = v_panel_clean, check_carrier = false
    where id = v.id returning * into v;
    perform private.log(v.site_id, format('Card %s unassigned from %s. In quarantine until cleaned up.', v.card_number, v.holder_name));
  end if;
  return v;
end;
$$;

create or replace function public.set_cleanup(p_credential uuid, p_panel boolean, p_carrier boolean) returns public.credentials
language plpgsql security definer set search_path = '' as $$
declare v public.credentials;
begin
  select * into v from public.credentials where id = p_credential for update;
  if not found then raise exception 'Credential not found'; end if;
  perform private.require_site(v.site_id);
  if v.status <> 'quarantine' then raise exception 'Credential isn''t in quarantine'; end if;
  update public.credentials set check_panel = coalesce(p_panel, check_panel), check_carrier = coalesce(p_carrier, check_carrier),
    updated_at = now() where id = v.id returning * into v;
  if p_panel then
    update public.panel_changes set done = true, done_at = now(), done_by = (select auth.uid())
     where credential_id = v.id and op = 'remove' and not done;
  end if;
  return v;
end;
$$;

create or replace function public.return_to_pool(p_credential uuid) returns public.credentials
language plpgsql security definer set search_path = '' as $$
declare v public.credentials; v_name text;
begin
  select * into v from public.credentials where id = p_credential for update;
  if not found then raise exception 'Credential not found'; end if;
  perform private.require_site(v.site_id);
  if v.status <> 'quarantine' then raise exception 'Credential isn''t in quarantine'; end if;
  if not (v.check_panel and v.check_carrier) then
    raise exception 'Finish both clean-up steps first (panel removal and carrier wiped/revoked)';
  end if;
  v_name := v.holder_name;
  update public.credentials set status = 'available', reuse_count = reuse_count + 1,
    carrier = null, holder_name = null, holder_email = null, assigned_at = null, expires_on = null,
    ready = false, invite_token = null, check_panel = false, check_carrier = false, freed_at = null, updated_at = now()
  where id = v.id returning * into v;
  perform private.log(v.site_id, format('Card %s cleaned up after %s and returned to the pool.', v.card_number, v_name));
  return v;
end;
$$;

create or replace function public.mark_change_done(p_change bigint) returns void
language plpgsql security definer set search_path = '' as $$
declare c public.panel_changes;
begin
  select * into c from public.panel_changes where id = p_change for update;
  if not found then raise exception 'Panel change not found'; end if;
  perform private.require_site(c.site_id);
  if c.done then return; end if;
  update public.panel_changes set done = true, done_at = now(), done_by = (select auth.uid()) where id = c.id;
  if c.op = 'remove' and c.credential_id is not null then
    update public.credentials set check_panel = true, updated_at = now()
     where id = c.credential_id and status = 'quarantine';
  end if;
  perform private.log(c.site_id, format('Panel updated: %s card %s %s %s.',
    case when c.op = 'add' then 'added' else 'removed' end, c.card_number,
    case when c.op = 'add' then 'for' else 'from' end, coalesce(c.holder_name, 'holder')));
end;
$$;

create or replace function public.add_site_owner(p_site uuid, p_email text) returns text
language plpgsql security definer set search_path = '' as $$
declare v_email text := lower(trim(coalesce(p_email, ''))); v_user uuid;
begin
  perform private.require_site(p_site, 'installer');
  if position('@' in v_email) < 2 then raise exception 'Enter a valid email'; end if;
  select id into v_user from auth.users where lower(email) = v_email limit 1;
  if v_user is not null then
    insert into public.memberships (user_id, site_id, role) values (v_user, p_site, 'owner') on conflict do nothing;
    perform private.log(p_site, format('%s added as a site owner.', v_email));
    return 'added';
  end if;
  insert into public.owner_invites (site_id, email, invited_by) values (p_site, v_email, (select auth.uid()))
    on conflict (site_id, email) do nothing;
  perform private.log(p_site, format('%s invited as a site owner.', v_email));
  return 'invited';
end;
$$;

create or replace function public.remove_site_owner(p_site uuid, p_email text) returns void
language plpgsql security definer set search_path = '' as $$
declare v_email text := lower(trim(coalesce(p_email, '')));
begin
  perform private.require_site(p_site, 'installer');
  delete from public.memberships m using auth.users u
   where m.user_id = u.id and m.site_id = p_site and m.role = 'owner' and lower(u.email) = v_email;
  delete from public.owner_invites where site_id = p_site and email = v_email;
  perform private.log(p_site, format('%s removed as a site owner.', v_email));
end;
$$;

-- Owners of a site, with emails (the installer's view).
create or replace function public.site_owners(p_site uuid) returns table (email text, status text)
language plpgsql stable security definer set search_path = '' as $$
begin
  perform private.require_site(p_site, 'installer');
  return query
    select u.email::text, 'active'::text from public.memberships m join auth.users u on u.id = m.user_id
     where m.site_id = p_site and m.role = 'owner'
    union all
    select i.email, 'invited' from public.owner_invites i where i.site_id = p_site
    order by 1;
end;
$$;

-- Called after sign-in: turns any owner invites for this email into memberships.
create or replace function public.claim_invites() returns integer
language plpgsql security definer set search_path = '' as $$
declare v_uid uuid := (select auth.uid()); v_email text; v_n integer;
begin
  if v_uid is null then return 0; end if;
  select lower(email) into v_email from auth.users where id = v_uid and email_confirmed_at is not null;
  if v_email is null then return 0; end if;
  insert into public.memberships (user_id, site_id, role)
    select v_uid, i.site_id, 'owner' from public.owner_invites i where i.email = v_email
    on conflict do nothing;
  get diagnostics v_n = row_count;
  delete from public.owner_invites where email = v_email;
  return v_n;
end;
$$;

do $$
declare f text;
begin
  foreach f in array array[
    'public.create_installer(text)', 'public.create_site(uuid,text,integer,text,integer)', 'public.topup_pool(uuid,integer)',
    'public.request_topup(uuid)', 'public.assign_credential(uuid,text,text,text,date,bigint)', 'public.mark_ready(uuid)',
    'public.unassign_credential(uuid,text)', 'public.set_cleanup(uuid,boolean,boolean)', 'public.return_to_pool(uuid)',
    'public.mark_change_done(bigint)', 'public.add_site_owner(uuid,text)', 'public.remove_site_owner(uuid,text)',
    'public.site_owners(uuid)', 'public.claim_invites()']
  loop
    execute format('revoke all on function %s from public, anon', f);
    execute format('grant execute on function %s to authenticated', f);
  end loop;
end $$;
revoke all on function private.max_card(text) from public, anon;
grant execute on function private.max_card(text) to authenticated;
