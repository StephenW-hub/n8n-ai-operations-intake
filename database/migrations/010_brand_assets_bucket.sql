-- Module 7: public-read bucket for client logos (email clients can only show logos from a public
-- https URL). Uploads happen only from n8n with the service key ("Supabase Storage – Ops Intake"
-- credential); there are no anon/authenticated write policies. PNG, JPEG and WEBP only (no SVG,
-- which can carry script and is blocked by many email clients), 500 KB max.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('brand-assets', 'brand-assets', true, 512000, array['image/png', 'image/jpeg', 'image/webp'])
on conflict (id) do update
   set public = excluded.public, file_size_limit = excluded.file_size_limit,
       allowed_mime_types = excluded.allowed_mime_types;
