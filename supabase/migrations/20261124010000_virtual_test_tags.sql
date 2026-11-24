-- Test tags before real NTAG 424 DNA stock arrives.
-- Virtual tags: no hardware; the server signs taps with the tag's real keys (encoder test_tap).
alter table public.tags add column if not exists is_virtual boolean not null default false;
alter table public.tags add column if not exists virtual_ctr integer not null default 0;
alter table public.tags add column if not exists virtual_last_url text;
