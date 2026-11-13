-- gooseGTP: удаление своих публикаций
-- Выполнить целиком в Supabase -> SQL Editor -> Run (достаточно один раз).

-- 1) Пользователь может удалять только свои записи в каталоге.
drop policy if exists "Users can delete own products" on public.products;
create policy "Users can delete own products" on public.products
for delete to authenticated using (created_by = (select auth.uid()));

-- 2) Пользователь может удалять файлы из своей папки в bucket downloads.
--    Файлы загружаются по пути "<user_id>/<id>-<имя>", поэтому проверяем первый сегмент пути.
drop policy if exists "Users can delete own downloads" on storage.objects;
create policy "Users can delete own downloads" on storage.objects
for delete to authenticated using (
  bucket_id = 'downloads'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);
