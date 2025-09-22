create or replace function audit.log_event(
  p_actor_id uuid,
  p_actor_subject text,
  p_action text,
  p_path text,
  p_extra jsonb
) returns void
language sql
security definer
set search_path = audit, pg_temp
as $$
  insert into audit.audit_logs(actor_id, actor_subject, action, path, extra)
  values (p_actor_id, p_actor_subject, p_action, p_path, p_extra);
$$;

revoke all on function audit.log_event(uuid,text,text,text,jsonb) from public;
grant execute on function audit.log_event(uuid,text,text,text,jsonb) to confmgr_db;