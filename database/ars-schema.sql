create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated, service_role;
create table private.admin_users (user_id uuid primary key references auth.users(id) on delete cascade);
alter table private.admin_users enable row level security;
create table private.signup_limits (key text primary key, window_start timestamptz not null, attempts integer not null);
alter table private.signup_limits enable row level security;
create function private.is_admin() returns boolean language sql stable security definer set search_path = '' as $$
 select (select auth.uid()) is not null and exists(select 1 from private.admin_users where user_id=(select auth.uid()));
$$;
revoke all on function private.is_admin() from public, anon;
grant execute on function private.is_admin() to authenticated;
create function public.admin_status() returns boolean language sql stable security invoker set search_path='' as $$select private.is_admin();$$;
revoke all on function public.admin_status() from public,anon;
grant execute on function public.admin_status() to authenticated;

create table public.profiles (
 user_id uuid primary key references auth.users(id) on delete cascade,
 full_name text not null check(char_length(full_name) between 1 and 100),
 phone text not null default '' check(char_length(phone)<=40),
 created_at timestamptz not null default now()
);
create table public.products (
 id uuid primary key default gen_random_uuid(), slug text unique not null,
 name text not null, category text not null, description text not null,
 composition text not null, image text not null,
 price_amd integer not null check(price_amd>=0), price_unit text not null default 'կգ',
 is_demo boolean not null default true, published boolean not null default true, sort_order integer not null default 0
);
create table public.courses (
 id uuid primary key default gen_random_uuid(), slug text unique not null,
 title text not null, summary text not null, description text not null,
 image text not null, duration_minutes integer not null check(duration_minutes>0),
 price_amd integer not null check(price_amd>=0), outcomes jsonb not null default '[]',
 level text not null default 'Սկսնակ', is_demo boolean not null default true,
 published boolean not null default true, sort_order integer not null default 0
);
create table public.lessons (
 course_id uuid primary key references public.courses(id) on delete cascade,
 video_id text not null check(video_id ~ '^[A-Za-z0-9_-]{11}$'),
 description text not null, ingredients jsonb not null default '[]', chapters jsonb not null default '[]',
 is_demo boolean not null default true
);
create table public.payment_requests (
 id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id) on delete cascade,
 course_id uuid not null references public.courses(id),
 amount_amd integer not null check(amount_amd>=0),
 status text not null default 'pending' check(status in ('pending','approved','rejected')),
 contact_phone text not null check(char_length(contact_phone) between 5 and 40),
 customer_note text not null default '' check(char_length(customer_note)<=500),
 admin_note text not null default '' check(char_length(admin_note)<=500),
 created_at timestamptz not null default now(), reviewed_at timestamptz, reviewed_by uuid references auth.users(id),
 unique(user_id,course_id)
);
create index payment_requests_course_idx on public.payment_requests(course_id);
create index payment_requests_reviewer_idx on public.payment_requests(reviewed_by);
create index payment_requests_status_idx on public.payment_requests(status,created_at desc);
create table public.entitlements (
 user_id uuid not null references auth.users(id) on delete cascade,
 course_id uuid not null references public.courses(id),
 granted_at timestamptz not null default now(), granted_by uuid references auth.users(id),
 primary key(user_id,course_id)
);
create index entitlements_course_idx on public.entitlements(course_id);
create index entitlements_granter_idx on public.entitlements(granted_by);
create table public.site_settings (
 id integer primary key check(id=1), payment_bank text not null, payment_account text not null,
 payment_recipient text not null, payment_phone text not null,
 payment_note text not null, is_demo boolean not null default true
);

alter table public.profiles enable row level security;
alter table public.products enable row level security;
alter table public.courses enable row level security;
alter table public.lessons enable row level security;
alter table public.payment_requests enable row level security;
alter table public.entitlements enable row level security;
alter table public.site_settings enable row level security;
revoke all on public.profiles,public.products,public.courses,public.lessons,public.payment_requests,public.entitlements,public.site_settings from anon,authenticated;
grant select on public.products,public.courses,public.site_settings to anon,authenticated;
grant select,insert,update on public.profiles to authenticated;
grant select on public.lessons,public.payment_requests,public.entitlements to authenticated;
grant insert,update,delete on public.products,public.courses,public.lessons,public.site_settings to authenticated;
create policy profile_read on public.profiles for select to authenticated using(user_id=(select auth.uid()) or (select private.is_admin()));
create policy profile_create on public.profiles for insert to authenticated with check(user_id=(select auth.uid()));
create policy profile_update on public.profiles for update to authenticated using(user_id=(select auth.uid())) with check(user_id=(select auth.uid()));
create policy products_public on public.products for select to anon,authenticated using(published);
create policy products_admin on public.products for all to authenticated using((select private.is_admin())) with check((select private.is_admin()));
create policy courses_public on public.courses for select to anon,authenticated using(published);
create policy courses_admin on public.courses for all to authenticated using((select private.is_admin())) with check((select private.is_admin()));
create policy settings_public on public.site_settings for select to anon,authenticated using(true);
create policy settings_admin on public.site_settings for all to authenticated using((select private.is_admin())) with check((select private.is_admin()));
create policy lessons_owned on public.lessons for select to authenticated using(exists(select 1 from public.entitlements e where e.course_id=lessons.course_id and e.user_id=(select auth.uid())) or (select private.is_admin()));
create policy lessons_admin on public.lessons for all to authenticated using((select private.is_admin())) with check((select private.is_admin()));
create policy requests_read on public.payment_requests for select to authenticated using(user_id=(select auth.uid()) or (select private.is_admin()));
create policy entitlements_read on public.entitlements for select to authenticated using(user_id=(select auth.uid()) or (select private.is_admin()));

-- Purchase price and identity are taken from the database, never from a client.
create function private.request_purchase(p_course_id uuid,p_phone text,p_note text) returns uuid
language plpgsql security definer set search_path='' as $$
declare v_uid uuid:=auth.uid(); v_price integer; v_id uuid;
begin
 if v_uid is null then raise exception 'Authentication required'; end if;
 if length(trim(p_phone)) not between 5 and 40 or length(p_note)>500 then raise exception 'Invalid contact details'; end if;
 select price_amd into v_price from public.courses where id=p_course_id and published;
 if not found then raise exception 'Course unavailable'; end if;
 if exists(select 1 from public.entitlements where user_id=v_uid and course_id=p_course_id) then raise exception 'Already enrolled'; end if;
 insert into public.payment_requests(user_id,course_id,amount_amd,contact_phone,customer_note)
 values(v_uid,p_course_id,v_price,trim(p_phone),p_note)
 on conflict(user_id,course_id) do update set status='pending',amount_amd=excluded.amount_amd,contact_phone=excluded.contact_phone,customer_note=excluded.customer_note,admin_note='',reviewed_at=null,reviewed_by=null,created_at=now()
 where payment_requests.status='rejected'
 returning id into v_id;
 if v_id is null then select id into v_id from public.payment_requests where user_id=v_uid and course_id=p_course_id; end if;
 return v_id;
end;$$;
revoke all on function private.request_purchase(uuid,text,text) from public,anon;
grant execute on function private.request_purchase(uuid,text,text) to authenticated;
create function public.request_purchase(p_course_id uuid,p_phone text,p_note text default '') returns uuid language sql security invoker set search_path='' as $$select private.request_purchase(p_course_id,p_phone,p_note);$$;
revoke all on function public.request_purchase(uuid,text,text) from public,anon;
grant execute on function public.request_purchase(uuid,text,text) to authenticated;

-- Owner approval and access grant are atomic. Students cannot call this successfully.
create function private.review_payment(p_request_id uuid,p_approve boolean,p_note text) returns void
language plpgsql security definer set search_path='' as $$
declare v_request public.payment_requests;
begin
 if auth.uid() is null or not private.is_admin() then raise exception 'Administrator required'; end if;
 if length(p_note)>500 then raise exception 'Note too long'; end if;
 select * into v_request from public.payment_requests where id=p_request_id for update;
 if not found then raise exception 'Request not found'; end if;
 if v_request.status<>'pending' then raise exception 'Request already reviewed'; end if;
 update public.payment_requests set status=case when p_approve then 'approved' else 'rejected' end,admin_note=p_note,reviewed_at=now(),reviewed_by=auth.uid() where id=p_request_id;
 if p_approve then insert into public.entitlements(user_id,course_id,granted_by) values(v_request.user_id,v_request.course_id,auth.uid()) on conflict do nothing; end if;
end;$$;
revoke all on function private.review_payment(uuid,boolean,text) from public,anon;
grant execute on function private.review_payment(uuid,boolean,text) to authenticated;
create function public.review_payment(p_request_id uuid,p_approve boolean,p_note text default '') returns void language sql security invoker set search_path='' as $$select private.review_payment(p_request_id,p_approve,p_note);$$;
revoke all on function public.review_payment(uuid,boolean,text) from public,anon;
grant execute on function public.review_payment(uuid,boolean,text) to authenticated;

-- Public signup edge function is rate-limited persistently; only service_role can call this RPC.
create function private.signup_rate_limit(p_key text) returns boolean language plpgsql security definer set search_path='' as $$
declare v_count integer;
begin
 insert into private.signup_limits(key,window_start,attempts) values(p_key,date_trunc('hour',now()),1)
 on conflict(key) do update set attempts=case when signup_limits.window_start<date_trunc('hour',now()) then 1 else signup_limits.attempts+1 end,window_start=date_trunc('hour',now()) returning attempts into v_count;
 return v_count<=8;
end;$$;
revoke all on function private.signup_rate_limit(text) from public,anon,authenticated;
grant execute on function private.signup_rate_limit(text) to service_role;
create function public.signup_rate_limit(p_key text) returns boolean language sql security invoker set search_path='' as $$select private.signup_rate_limit(p_key);$$;
revoke all on function public.signup_rate_limit(text) from public,anon,authenticated;
grant execute on function public.signup_rate_limit(text) to service_role;
