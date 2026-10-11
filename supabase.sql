-- GlassChat database setup. Run in Supabase Dashboard > SQL Editor.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text unique,
  created_at timestamptz not null default now()
);
create table if not exists public.chats (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now()
);
create table if not exists public.chat_members (
  chat_id uuid not null references public.chats(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key(chat_id,user_id)
);
create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  chat_id uuid not null references public.chats(id) on delete cascade,
  sender_id uuid not null references auth.users(id) on delete cascade,
  content text not null check (char_length(content) between 1 and 4000),
  created_at timestamptz not null default now()
);
create index if not exists messages_chat_created_idx on public.messages(chat_id,created_at);

alter table public.profiles enable row level security;
alter table public.chats enable row level security;
alter table public.chat_members enable row level security;
alter table public.messages enable row level security;

-- Create/update a public profile when an auth user is created.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path=public
as $$
begin
  insert into public.profiles(id,email) values(new.id,lower(new.email))
  on conflict(id) do update set email=excluded.email;
  return new;
end;
$$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.is_chat_member(check_chat uuid, check_user uuid default auth.uid())
returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.chat_members where chat_id=check_chat and user_id=check_user); $$;

create policy "Users can see own profile and chat peers" on public.profiles
for select to authenticated using (
  id = auth.uid()
  or exists (
    select 1
    from public.chat_members mine
    join public.chat_members theirs on theirs.chat_id = mine.chat_id
    where mine.user_id = auth.uid() and theirs.user_id = profiles.id
  )
);
create policy "Users read chats they belong to" on public.chats
for select to authenticated using (public.is_chat_member(id));
create policy "Users read own memberships and chat peers" on public.chat_members
for select to authenticated using (public.is_chat_member(chat_id));
create policy "Members read messages" on public.messages
for select to authenticated using (public.is_chat_member(chat_id));
create policy "Members send messages as themselves" on public.messages
for insert to authenticated with check (
  sender_id=auth.uid() and public.is_chat_member(chat_id)
);

-- Search exact email (case-insensitive). The client never receives auth admin credentials.
create or replace function public.search_profiles(search_email text)
returns table(id uuid,email text)
language sql stable security definer set search_path=public
as $$
  select p.id,p.email from public.profiles p
  where auth.uid() is not null and lower(p.email)=lower(trim(search_email))
  limit 5;
$$;
grant execute on function public.search_profiles(text) to authenticated;

-- Create a one-to-one chat or return the existing one.
create or replace function public.create_or_get_chat(peer_user_id uuid)
returns uuid language plpgsql security definer set search_path=public
as $$
declare me uuid := auth.uid(); existing_chat uuid; new_chat uuid;
begin
  if me is null then raise exception 'Sign in required'; end if;
  if peer_user_id is null or peer_user_id=me then raise exception 'Invalid recipient'; end if;
  if not exists(select 1 from public.profiles where id=peer_user_id) then raise exception 'User not found'; end if;
  select cm1.chat_id into existing_chat
  from public.chat_members cm1
  join public.chat_members cm2 on cm1.chat_id=cm2.chat_id
  join public.chats c on c.id=cm1.chat_id
  where cm1.user_id=me and cm2.user_id=peer_user_id
    and (select count(*) from public.chat_members x where x.chat_id=cm1.chat_id)=2
  limit 1;
  if existing_chat is not null then return existing_chat; end if;
  insert into public.chats default values returning id into new_chat;
  insert into public.chat_members(chat_id,user_id) values(new_chat,me),(new_chat,peer_user_id);
  return new_chat;
end;
$$;
grant execute on function public.create_or_get_chat(uuid) to authenticated;

-- Enable realtime updates for messages. If this errors because it already exists, ignore it.
do $$ begin
  alter publication supabase_realtime add table public.messages;
exception when duplicate_object then null;
when others then raise notice 'Could not add messages to realtime publication: %', SQLERRM;
end $$;
