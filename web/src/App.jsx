import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Servers from './pages/Servers'
import Groups from './pages/Groups'
import Services from './pages/Services'
import Policies from './pages/Policies'
import Logs from './pages/Logs'
import { useAuthStore } from './store'
import { ToastProvider } from './hooks/ToastContext'
import ErrorBoundary from './components/ErrorBoundary'

const qc = new QueryClient()

function PrivateRoute({ children }) {
  const auth = useAuthStore(s => s.isAuthenticated)
  return auth ? children : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={qc}>
        <ToastProvider>
          <BrowserRouter>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="/" element={<PrivateRoute><Layout /></PrivateRoute>}>
                <Route index element={<Dashboard />} />
                <Route path="servers"  element={<Servers />} />
                <Route path="groups"   element={<Groups />} />
                <Route path="services" element={<Services />} />
                <Route path="policies" element={<Policies />} />
                <Route path="logs"     element={<Logs />} />
              </Route>
            </Routes>
          </BrowserRouter>
        </ToastProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  )
}
