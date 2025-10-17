import { Routes, Route, Navigate } from 'react-router-dom'
import Login from './pages/Login.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Secret from './pages/Secret.jsx'
import ConfigPage from './pages/Config.jsx'
import UsersPage from './pages/Users.jsx'
import AuditPage from './pages/Audit.jsx'
import WhoAmI from './pages/WhoAmI.jsx'
import AppLayout from './components/AppLayout.jsx'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Login />} />
      <Route path="/app" element={<AppLayout />}>
        <Route index element={<Dashboard />} />
        <Route path="secrets" element={<Secret />} />
        <Route path="configs" element={<ConfigPage />} />
        <Route path="users" element={<UsersPage />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="whoami" element={<WhoAmI />} />
      </Route>
      <Route path="/whoami" element={<Navigate to="/app/whoami" replace />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
