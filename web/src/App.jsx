import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SetupProvider, useSetup } from './contexts/SetupContext'
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

const qc = new QueryClient()

function PrivateRoute({ children }) {
  const auth = useAuthStore(s => s.isAuthenticated)
  return auth ? children : <SmartRedirect />
}

function SmartRedirect() {
  const navigate = useNavigate()
  const { needsSetup, loading } = useSetup()

  useEffect(() => {
    if (loading) return // Wait for state to load

    if (needsSetup === null) {
      // Error state, default to login
      navigate('/login', { replace: true })
    } else if (needsSetup) {
      navigate('/setup', { replace: true })
    } else {
      navigate('/login', { replace: true })
    }
  }, [navigate, needsSetup, loading])

  // Improved loading state with better visual feedback
  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-runic-600 dark:border-runic-400 mx-auto mb-4"></div>
          <p className="text-gray-600 dark:text-gray-400 text-lg">Checking setup status...</p>
        </div>
      </div>
    )
  }

  // Fallback (should redirect before rendering)
  return null
}

export default function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={qc}>
        <ToastProvider>
          <SetupProvider>
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
          </SetupProvider>
        </ToastProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  )
}
