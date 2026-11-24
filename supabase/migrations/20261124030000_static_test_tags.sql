-- MIFARE Ultralight / Ultralight EV1 / Ultralight C test tags: too small and too simple for a counter
-- mirror, so they carry a static link ?s=<short_code>. They prove the flow works, not authenticity.
alter table public.tags add column if not exists short_code text;
create unique index if not exists tags_short_code_key on public.tags (short_code) where short_code is not null;
alter table public.tags drop constraint if exists tags_chip_check;
alter table public.tags add constraint tags_chip_check check (chip in ('ntag424', 'ntag21x', 'ultralight', 'virtual'));
