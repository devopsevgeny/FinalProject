export default function UsersPage() {
  return (
    <div className="d-grid gap-3" style={{ maxWidth: 720 }}>
      <h3 style={{ marginTop: 0 }}>Manage users</h3>
      <p>
        The backend does not expose user-management endpoints yet.
        Until then, keep relying on your identity provider (or database scripts) to onboard and offboard operators.
      </p>
      <p>
        Once the API is available, this view can host role assignments, access reviews, and invitations.
      </p>
    </div>
  )
}
