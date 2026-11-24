-- Which chip a tag is: real NTAG 424 DNA, NTAG213/215/216 test tag (unsigned UID+counter mirror), or virtual.
alter table public.tags add column if not exists chip text not null default 'ntag424';
alter table public.tags drop constraint if exists tags_chip_check;
alter table public.tags add constraint tags_chip_check check (chip in ('ntag424', 'ntag21x', 'virtual'));
update public.tags set chip = 'virtual' where is_virtual and chip <> 'virtual';
