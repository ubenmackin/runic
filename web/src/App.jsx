import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom'
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
import { useEffect } from 'react'
import { api } from './api/client'

const qc = new QueryClient()

function PrivateRoute({ children }) {
  const auth = useAuthStore(s => s.isAuthenticated)
  return auth ? children : <SmartRedirect />
}

function SmartRedirect() {
  const navigate = useNavigate()

  useEffect(() => {
    // Check if setup is needed when user is not authenticated
    api.get('/setup')
      .then(data => {
        // Redirect to /setup if no users exist, otherwise /login
        if (data.needs_setup) {
          navigate('/setup', { replace: true })
        } else {
          navigate('/login', { replace: true })
        }
      })
      .catch(() => {
        // If the check fails, default to /login
        navigate('/login', { replace: true })
      })
  }, [navigate])

  // Show loading while checking setup status
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
      <div className="text-runic-600 dark:text-runic-400 text-xl">Loading...</div>
    </div>
  )
}

export default function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={qc}>
        <ToastProvider>
          <BrowserRouter>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="/setup" element={<Login mode="setup" />} />
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
