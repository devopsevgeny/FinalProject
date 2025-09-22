do $$
declare
  start_month date := date_trunc('month', now())::date;
  end_month   date := (date_trunc('month', now()) + interval '1 month')::date;
  part_name   text := 'audit_logs_' || to_char(start_month, 'YYYY_MM');
  p           text;
begin
  execute format(
    'create table if not exists audit.%I partition of audit.audit_logs
     for values from (%L) to (%L);',
    part_name, start_month, end_month
  );

  p := format('audit.%I', part_name);
  execute format('create index if not exists %I on %s(created_at);', 'idx_'||replace(part_name,'.','_')||'_created_at', p);
  execute format('create index if not exists %I on %s(actor_id, created_at);', 'idx_'||replace(part_name,'.','_')||'_actor_created', p);
  execute format('create index if not exists %I on %s(path, created_at);', 'idx_'||replace(part_name,'.','_')||'_path_created', p);
end$$;
