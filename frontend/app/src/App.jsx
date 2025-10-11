import { Routes, Route, Navigate } from 'react-router-dom'
import Login from './pages/Login.jsx'
import WhoAmI from './pages/WhoAmI.jsx'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Login />} />
      <Route path="/whoami" element={<WhoAmI />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
