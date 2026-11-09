-- ============================================================================
-- IE Billing — Auditor / CA login (Pass Key) — Supabase migration
-- File: supabase/migrations/20261109_auditor_passkeys.sql
--
-- HOW TO RUN (do this ONCE, in the Supabase dashboard):
--   1. Open Supabase Dashboard -> your project -> SQL Editor.
--   2. Paste the ENTIRE contents of this file and press Run.
--   3. Confirm it reports success (no errors).
--
-- Until this file has been run, the Auditor / CA login in the app will show a
-- clear English error ("Auditor login is not set up yet. Please ask the owner
-- to run the database setup.") instead of logging anyone in. Nothing else in
-- the app is affected: owner email/password and Google login keep working.
--
-- WHAT THIS CREATES:
--   * auditor_passkeys  — one row per Pass Key the owner creates. Only the
--     SHA-256 hash of the key is stored; the key itself is shown to the owner
--     ONCE at creation and is never stored or shown again.
--   * auditor_audit_log — append-only log of auditor logins, logouts,
--     exports, prints and page views. The app never deletes from it.
--   * SECURITY DEFINER functions auditor_create_passkey, auditor_verify_login,
--     auditor_revoke_passkey, auditor_list_passkeys, auditor_log_action and
--     auditor_get_data. All auditor checks and data reads go through these
--     functions, so the auditor path never reads another user's rows directly
--     with the anon key.
--   * RLS is enabled on both tables with deny-all policies for anon and
--     authenticated roles. Only the SECURITY DEFINER functions (running as
--     the table owner / postgres) can read or write them.
--
-- NOTES / CAVEATS:
--   * The existing fs_documents table is NOT changed by this file. RLS on
--     fs_documents could not be verified from the app code alone; please
--     confirm in the dashboard (Authentication -> Policies) that RLS is
--     enabled on fs_documents. Even if it is not, the auditor flow below does
--     not depend on direct anon reads of fs_documents: auditor data is only
--     returned by the SECURITY DEFINER function auditor_get_data().
--   * The owner's 10-digit Unique ID (owner_user_id) is the userProfile.userId
--     shown on My Profile in the app. It is NOT the Supabase Auth UID
--     (auth.uid()), which is never shown in the app.
-- ============================================================================

-- --------------------------------------------------------------------------
-- Tables
-- --------------------------------------------------------------------------

create table if not exists public.auditor_passkeys (
  id              uuid primary key default gen_random_uuid(),
  owner_uid       text not null,            -- Supabase Auth UID of the owner (currentUser.uid)
  owner_email     text not null,            -- owner email, lower-cased by the app
  owner_user_id   text not null,            -- owner's 10-digit Unique ID (userProfile.userId)
  auditor_email   text not null,            -- auditor/CA email the owner entered at creation
  passkey_hash    text not null,            -- SHA-256 hex of the Pass Key (key itself never stored)
  company_ids     text[] not null default '{}', -- allowed company ids; empty array = ALL companies
  expires_at      timestamptz not null,
  revoked         boolean not null default false,
  last_used_at    timestamptz,
  failed_attempts int not null default 0,
  locked_until    timestamptz,
  created_at      timestamptz not null default now()
);

create index if not exists auditor_passkeys_owner_idx
  on public.auditor_passkeys (owner_uid);
create index if not exists auditor_passkeys_lookup_idx
  on public.auditor_passkeys (owner_email, owner_user_id, auditor_email);

create table if not exists public.auditor_audit_log (
  id            uuid primary key default gen_random_uuid(),
  owner_uid     text not null,
  auditor_email text not null,
  auditor_name  text not null default '',
  action        text not null,              -- e.g. 'login', 'logout', 'export', 'print', 'view'
  detail        text not null default '',
  created_at    timestamptz not null default now()
);

create index if not exists auditor_audit_log_owner_idx
  on public.auditor_audit_log (owner_uid, created_at desc);

-- --------------------------------------------------------------------------
-- Row Level Security: deny-all for anon / authenticated.
-- Access is only through the SECURITY DEFINER functions below.
-- --------------------------------------------------------------------------

alter table public.auditor_passkeys enable row level security;
alter table public.auditor_audit_log enable row level security;

-- Deny-all policies (no USING / WITH CHECK that ever returns true).
drop policy if exists "auditor_passkeys deny all" on public.auditor_passkeys;
create policy "auditor_passkeys deny all" on public.auditor_passkeys
  for all to anon, authenticated using (false) with check (false);

drop policy if exists "auditor_audit_log deny all" on public.auditor_audit_log;
create policy "auditor_audit_log deny all" on public.auditor_audit_log
  for all to anon, authenticated using (false) with check (false);

-- --------------------------------------------------------------------------
-- Helper: resolve the owner's companies from fs_documents.
-- Company docs live at collection_path = 'users/<owner_uid>/companies'
-- with doc_id = company id. The company name is stored in data->>'name'
-- (falling back to data->>'companyName' / doc id when absent).
-- --------------------------------------------------------------------------

create or replace function public.auditor_owner_companies(p_owner_uid text)
returns table (company_id text, company_name text)
language sql
security definer
set search_path = public
as $$
  select d.doc_id as company_id,
         coalesce(nullif(d.data ->> 'name', ''), nullif(d.data ->> 'companyName', ''), d.doc_id) as company_name
  from public.fs_documents d
  where d.collection_path = 'users/' || p_owner_uid || '/companies'
  order by coalesce(nullif(d.data ->> 'name', ''), d.doc_id);
$$;

-- --------------------------------------------------------------------------
-- auditor_create_passkey
-- Called by the OWNER (from Audit & Security > Roles & PIN, after entering
-- the Owner PIN). Stores only the SHA-256 hash of the Pass Key.
-- p_company_ids: array of allowed company ids; empty array = all companies.
-- Returns the new passkey id.
-- --------------------------------------------------------------------------

create or replace function public.auditor_create_passkey(
  p_owner_uid text,
  p_owner_email text,
  p_owner_user_id text,
  p_auditor_email text,
  p_company_ids text[],
  p_expires_at timestamptz,
  p_passkey_hash text
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_id uuid;
begin
  if p_owner_uid is null or p_owner_uid = '' then
    raise exception 'owner_uid is required';
  end if;
  if p_owner_email is null or p_owner_email = '' then
    raise exception 'owner_email is required';
  end if;
  if p_owner_user_id is null or p_owner_user_id = '' then
    raise exception 'owner_user_id is required';
  end if;
  if p_auditor_email is null or p_auditor_email = '' then
    raise exception 'auditor_email is required';
  end if;
  if p_expires_at is null or p_expires_at <= now() then
    raise exception 'expires_at must be in the future';
  end if;
  if p_passkey_hash is null or p_passkey_hash = '' then
    raise exception 'passkey_hash is required';
  end if;

  insert into public.auditor_passkeys
    (owner_uid, owner_email, owner_user_id, auditor_email,
     passkey_hash, company_ids, expires_at)
  values
    (p_owner_uid, lower(p_owner_email), p_owner_user_id,
     lower(p_auditor_email),
     p_passkey_hash, coalesce(p_company_ids, '{}'), p_expires_at)
  returning id into v_id;

  return v_id;
end;
$$;

-- --------------------------------------------------------------------------
-- auditor_verify_login
-- Called by the AUDITOR login tab. Checks, in order:
--   1. a passkey row exists for (owner email, 10-digit user id, auditor email)
--   2. it is not revoked
--   3. it is not expired
--   4. it is not locked (5 wrong attempts -> 15 minute lock)
--   5. the SHA-256 hash matches
-- On a wrong hash it increments failed_attempts and locks after 5 attempts.
-- On success it resets failed_attempts, updates last_used_at and returns the
-- owner's uid plus the allowed companies (resolved from the owner's user doc).
-- Return columns:
--   status        text  'ok' | 'bad' | 'locked' | 'expired' | 'revoked' | 'nopin'
--   owner_uid     text  (only when status = 'ok')
--   owner_email   text
--   companies     jsonb [{id, name}] allowed for this passkey (all when empty)
--   expires_at    timestamptz (only when status = 'ok')
--   locked_until  timestamptz (only when status = 'locked')
-- --------------------------------------------------------------------------

create or replace function public.auditor_verify_login(
  p_owner_email text,
  p_user_id text,
  p_auditor_email text,
  p_passkey_hash text
)
returns table (
  status text,
  owner_uid text,
  owner_email text,
  companies jsonb,
  expires_at timestamptz,
  locked_until timestamptz
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_row public.auditor_passkeys%rowtype;
  v_companies jsonb;
begin
  select * into v_row
  from public.auditor_passkeys
  where lower(owner_email) = lower(p_owner_email)
    and owner_user_id = p_user_id
    and lower(auditor_email) = lower(p_auditor_email)
  order by created_at desc
  limit 1;

  if not found then
    return query select 'nopin'::text, null::text, null::text,
                        null::jsonb, null::timestamptz, null::timestamptz;
    return;
  end if;

  if v_row.revoked then
    return query select 'revoked'::text, null::text, null::text,
                        null::jsonb, null::timestamptz, null::timestamptz;
    return;
  end if;

  if v_row.expires_at <= now() then
    return query select 'expired'::text, null::text, null::text,
                        null::jsonb, null::timestamptz, null::timestamptz;
    return;
  end if;

  if v_row.locked_until is not null and v_row.locked_until > now() then
    return query select 'locked'::text, null::text, null::text,
                        null::jsonb, null::timestamptz, v_row.locked_until;
    return;
  end if;

  if v_row.passkey_hash <> p_passkey_hash then
    update public.auditor_passkeys
    set failed_attempts = failed_attempts + 1,
        locked_until = case
          when failed_attempts + 1 >= 5 then now() + interval '15 minutes'
          else locked_until
        end
    where id = v_row.id;

    if v_row.failed_attempts + 1 >= 5 then
      return query select 'locked'::text, null::text, null::text,
                          null::jsonb, null::timestamptz, now() + interval '15 minutes';
    end if;

    return query select 'bad'::text, null::text, null::text,
                        null::jsonb, null::timestamptz, null::timestamptz;
    return;
  end if;

  -- Success: reset failures, stamp last use, resolve allowed companies.
  update public.auditor_passkeys
  set failed_attempts = 0, locked_until = null, last_used_at = now()
  where id = v_row.id;

  select coalesce(jsonb_agg(jsonb_build_object('id', c.company_id, 'name', c.company_name)), '[]'::jsonb)
    into v_companies
  from public.auditor_owner_companies(v_row.owner_uid) c
  where cardinality(v_row.company_ids) = 0
     or c.company_id = any (v_row.company_ids);

  return query select 'ok'::text, v_row.owner_uid, v_row.owner_email,
                      v_companies, v_row.expires_at, null::timestamptz;
end;
$$;

-- --------------------------------------------------------------------------
-- auditor_revoke_passkey — owner revokes a Pass Key (it stops working at once).
-- Returns true when a row was revoked.
-- --------------------------------------------------------------------------

create or replace function public.auditor_revoke_passkey(
  p_owner_uid text,
  p_passkey_id uuid
)
returns boolean
language sql
security definer
set search_path = public
as $$
  update public.auditor_passkeys
  set revoked = true
  where id = p_passkey_id and owner_uid = p_owner_uid
  returning true;
$$;

-- --------------------------------------------------------------------------
-- auditor_list_passkeys — owner lists their Pass Keys (hashes are never
-- returned). Returns one row per key, newest first.
-- --------------------------------------------------------------------------

create or replace function public.auditor_list_passkeys(p_owner_uid text)
returns table (
  id uuid,
  auditor_email text,
  company_ids text[],
  company_names text[],
  expires_at timestamptz,
  revoked boolean,
  last_used_at timestamptz,
  created_at timestamptz,
  failed_attempts int,
  locked_until timestamptz
)
language sql
security definer
set search_path = public
as $$
  select k.id,
         k.auditor_email,
         k.company_ids,
         array(
           select coalesce(nullif(d.data ->> 'name', ''), d.doc_id)
           from public.fs_documents d
           where d.collection_path = 'users/' || k.owner_uid || '/companies'
             and (cardinality(k.company_ids) = 0 or d.doc_id = any (k.company_ids))
         ) as company_names,
         k.expires_at,
         k.revoked,
         k.last_used_at,
         k.created_at,
         k.failed_attempts,
         k.locked_until
  from public.auditor_passkeys k
  where k.owner_uid = p_owner_uid
  order by k.created_at desc;
$$;

-- --------------------------------------------------------------------------
-- auditor_log_action — append-only log. Fire-and-forget from the app:
-- login, logout, export, print, view. Never throws for a bad action name;
-- callers must never block the UI on this call.
-- --------------------------------------------------------------------------

create or replace function public.auditor_log_action(
  p_owner_uid text,
  p_auditor_email text,
  p_auditor_name text,
  p_action text,
  p_detail text
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_id uuid;
begin
  insert into public.auditor_audit_log
    (owner_uid, auditor_email, auditor_name, action, detail)
  values
    (p_owner_uid, lower(coalesce(p_auditor_email, '')), coalesce(p_auditor_name, ''),
     coalesce(p_action, ''), coalesce(p_detail, ''))
  returning id into v_id;
  return v_id;
end;
$$;

-- --------------------------------------------------------------------------
-- auditor_get_data — returns the allowed companies' data for a verified
-- auditor session. The app calls this right after auditor_verify_login
-- succeeds and must pass the SAME owner uid / auditor email / passkey hash.
-- Returns one row per stored document:
--   collection_path text, doc_id text, data jsonb
-- covering:
--   * users/<owner_uid>/companies/<cid>            (company doc)
--   * users/<owner_uid>/companies/<cid>/parts/*    (invoice/payment/etc parts)
--   * users/<owner_uid>/companies/<cid>/invoices/* (single invoices)
--   * users/<owner_uid>/companies/<cid>/parts/meta and invoices_index
-- The passkey must still be valid (not revoked / expired / locked) and the
-- hash must match, otherwise zero rows are returned.
-- --------------------------------------------------------------------------

create or replace function public.auditor_get_data(
  p_owner_uid text,
  p_auditor_email text,
  p_passkey_hash text,
  p_company_ids text[]
)
returns table (
  collection_path text,
  doc_id text,
  data jsonb
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_ok boolean;
begin
  select exists (
    select 1
    from public.auditor_passkeys k
    where k.owner_uid = p_owner_uid
      and lower(k.auditor_email) = lower(p_auditor_email)
      and k.passkey_hash = p_passkey_hash
      and not k.revoked
      and k.expires_at > now()
      and (k.locked_until is null or k.locked_until <= now())
      and (cardinality(p_company_ids) = 0
           or cardinality(k.company_ids) = 0
           or k.company_ids && p_company_ids)
  ) into v_ok;

  if not v_ok then
    return;
  end if;

  return query
    select d.collection_path, d.doc_id, d.data
    from public.fs_documents d
    where (
      -- the company doc itself: collection_path 'users/<uid>/companies', doc_id = company id
      (d.collection_path = 'users/' || p_owner_uid || '/companies'
        and (cardinality(p_company_ids) = 0 or d.doc_id = any (p_company_ids)))
      -- everything stored under a company: parts, invoices, indexes
      or (d.collection_path like 'users/' || p_owner_uid || '/companies/%'
        and (cardinality(p_company_ids) = 0
             or split_part(d.collection_path, '/', 4) = any (p_company_ids)))
    );
end;
$$;

-- --------------------------------------------------------------------------
-- Permissions: the anon and authenticated roles may EXECUTE the functions
-- (they are SECURITY DEFINER, so the functions run with the owner's rights
-- and RLS on the tables does not apply inside them). Direct table access
-- stays denied by the deny-all policies above.
-- --------------------------------------------------------------------------

grant execute on function public.auditor_owner_companies(text) to anon, authenticated;
grant execute on function public.auditor_create_passkey(text, text, text, text, text[], timestamptz, text) to anon, authenticated;
grant execute on function public.auditor_verify_login(text, text, text, text) to anon, authenticated;
grant execute on function public.auditor_revoke_passkey(text, uuid) to anon, authenticated;
grant execute on function public.auditor_list_passkeys(text) to anon, authenticated;
grant execute on function public.auditor_log_action(text, text, text, text, text) to anon, authenticated;
grant execute on function public.auditor_get_data(text, text, text, text[]) to anon, authenticated;

-- End of migration.
