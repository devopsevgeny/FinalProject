export default function AuditPage() {
  return (
    <div className="d-grid gap-3" style={{ maxWidth: 720 }}>
      <h3 style={{ marginTop: 0 }}>Audit log</h3>
      <p>
        Backend auditing is already recording events each time you log in or modify configs and secrets.
        This screen will surface that feed once the API is published.
      </p>
      <p>
        For now you can inspect the <code>audit.log_event</code> table directly in Postgres or expose a read-only endpoint
        that returns the latest entries for this UI to render.
      </p>
    </div>
  )
}
