-- gooseGTP: профили, администратор, каталог и Storage policies
-- Выполнить целиком в Supabase -> SQL Editor -> Run.

-- 1) Расширяем существующую таблицу profiles (она уже создана в проекте).
alter table public.profiles add column if not exists username text;
alter table public.profiles add column if not exists is_admin boolean not null default false;

-- Уникальность логина без учёта регистра.
create unique index if not exists profiles_username_lower_uidx
on public.profiles (lower(username)) where username is not null;

-- 2) Автоматически создаём профиль при регистрации через Supabase Auth.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, username, is_admin)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'username', split_part(new.email, '@', 1)), false)
  on conflict (id) do update
    set username = excluded.username;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- 3) Защищённая функция проверки роли.
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.is_admin = true
  );
$$;
revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to authenticated;

-- Пользователь может читать только собственный профиль.
alter table public.profiles enable row level security;
drop policy if exists "Users can read own profile" on public.profiles;
create policy "Users can read own profile" on public.profiles
for select to authenticated using (id = (select auth.uid()));
revoke insert, update, delete on public.profiles from anon, authenticated;

-- 4) Каталог опубликованных материалов.
create table if not exists public.products (
  id uuid primary key,
  title text not null,
  category text not null check (category in ('extensions','apps','games')),
  description text not null,
  file_name text not null,
  file_path text not null unique,
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.products enable row level security;
drop policy if exists "Anyone can read published products" on public.products;
create policy "Anyone can read published products" on public.products
for select to anon, authenticated using (true);
drop policy if exists "Admins can publish products" on public.products;
create policy "Admins can publish products" on public.products
for insert to authenticated with check ((select public.is_admin()) and created_by = (select auth.uid()));
drop policy if exists "Admins can delete products" on public.products;
create policy "Admins can delete products" on public.products
for delete to authenticated using ((select public.is_admin()));
-- Любой пользователь может удалить свою публикацию.
drop policy if exists "Users can delete own products" on public.products;
create policy "Users can delete own products" on public.products
for delete to authenticated using (created_by = (select auth.uid()));
revoke insert, update, delete on public.products from anon;
grant select on public.products to anon, authenticated;
grant insert, delete on public.products to authenticated;

-- 5) Storage: downloads bucket уже создан как PUBLIC.
drop policy if exists "Admins can upload downloads" on storage.objects;
create policy "Admins can upload downloads" on storage.objects
for insert to authenticated with check (bucket_id = 'downloads' and (select public.is_admin()));
drop policy if exists "Admins can update downloads" on storage.objects;
create policy "Admins can update downloads" on storage.objects
for update to authenticated using (bucket_id = 'downloads' and (select public.is_admin()))
with check (bucket_id = 'downloads' and (select public.is_admin()));
drop policy if exists "Admins can delete downloads" on storage.objects;
create policy "Admins can delete downloads" on storage.objects
for delete to authenticated using (bucket_id = 'downloads' and (select public.is_admin()));
-- Пользователь может удалить файлы из своей папки (путь начинается с его id).
drop policy if exists "Users can delete own downloads" on storage.objects;
create policy "Users can delete own downloads" on storage.objects
for delete to authenticated using (
  bucket_id = 'downloads'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

-- 6) После регистрации своего аккаунта назначь его администратором:
-- замени email@example.com на свой Email и выполни отдельно:
-- update public.profiles
-- set is_admin = true
-- where id = (select id from auth.users where email = 'email@example.com');
