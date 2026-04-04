import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SetupProvider, useSetup } from './contexts/SetupContext'
import { PendingChangesProvider } from './contexts/PendingChangesContext'
import Layout from './components/Layout'
import { useAuthStore } from './store'
import { ToastProvider } from './hooks/ToastContext'
import ErrorBoundary, { RouteErrorBoundary } from './components/ErrorBoundary'
import { useEffect, Suspense, lazy } from 'react'

// Lazy load page components for code splitting
const Login = lazy(() => import('./pages/Login'))
const Dashboard = lazy(() => import('./pages/Dashboard'))
const Peers = lazy(() => import('./pages/Peers'))
const Groups = lazy(() => import('./pages/Groups'))
const Services = lazy(() => import('./pages/Services'))
const Policies = lazy(() => import('./pages/Policies'))
const Topology = lazy(() => import('./pages/Topology'))
const Logs = lazy(() => import('./pages/Logs'))
const SetupKeys = lazy(() => import('./pages/SetupKeys'))
const Users = lazy(() => import('./pages/Users'))
const Settings = lazy(() => import('./pages/Settings'))

// Loading fallback component for suspense boundaries
function PageLoader() {
  return (
<div className="min-h-screen bg-gray-50 dark:bg-charcoal-darkest flex items-center justify-center">
			<div className="text-center">
				<div className="animate-spin rounded-full h-12 w-12 border-b-2 border-runic-600 dark:border-purple-active mx-auto mb-4"></div>
				<p className="text-gray-600 dark:text-amber-muted text-lg">Loading...</p>
      </div>
    </div>
  )
}

const qc = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30000, // 30 seconds - data stays fresh
      gcTime: 300000, // 5 minutes - unused data garbage collected
      refetchOnWindowFocus: false, // Disable auto-refetch on window focus
    },
  },
})

function AuthCheck() {
  useEffect(() => {
    useAuthStore.getState().checkAuth()
  }, [])
  return null
}

function PrivateRoute({ children }) {
  const auth = useAuthStore(s => s.isAuthenticated)
  if (auth === null) return <PageLoader />  // still checking
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
<div className="min-h-screen bg-gray-50 dark:bg-charcoal-darkest flex items-center justify-center">
				<div className="text-center">
					<div className="animate-spin rounded-full h-12 w-12 border-b-2 border-runic-600 dark:border-purple-active mx-auto mb-4"></div>
					<p className="text-gray-600 dark:text-amber-muted text-lg">Checking setup status...</p>
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
      <AuthCheck />
      <QueryClientProvider client={qc}>
        <ToastProvider>
          <SetupProvider>
            <BrowserRouter>
              <Routes>
                <Route path="/login" element={<RouteErrorBoundary><Suspense fallback={<PageLoader />}><Login /></Suspense></RouteErrorBoundary>} />
        <Route path="/setup" element={<RouteErrorBoundary><Suspense fallback={<PageLoader />}><Login mode="setup" /></Suspense></RouteErrorBoundary>} />
        <Route path="/" element={
          <PrivateRoute>
            <PendingChangesProvider>
              <Layout />
            </PendingChangesProvider>
          </PrivateRoute>
        }>
          <Route index element={<RouteErrorBoundary><Suspense fallback={<PageLoader />}><Dashboard /></Suspense></RouteErrorBoundary>} />
                  <Route path="topology" element={<RouteErrorBoundary><Suspense fallback={<PageLoader />}><Topology /></Suspense></RouteErrorBoundary>} />
                  <Route path="peers" element={<RouteErrorBoundary><Suspense fallback={<PageLoader />}><Peers /></Suspense></RouteErrorBoundary>} />
                  <Route path="groups" element={<RouteErrorBoundary><Suspense fallback={<PageLoader />}><Groups /></Suspense></RouteErrorBoundary>} />
                  <Route path="services" element={<RouteErrorBoundary><Suspense fallback={<PageLoader />}><Services /></Suspense></RouteErrorBoundary>} />
                  <Route path="policies" element={<RouteErrorBoundary><Suspense fallback={<PageLoader />}><Policies /></Suspense></RouteErrorBoundary>} />
                  <Route path="logs" element={<RouteErrorBoundary><Suspense fallback={<PageLoader />}><Logs /></Suspense></RouteErrorBoundary>} />
                  <Route path="setup-keys" element={<RouteErrorBoundary><Suspense fallback={<PageLoader />}><SetupKeys /></Suspense></RouteErrorBoundary>} />
                  <Route path="users" element={<RouteErrorBoundary><Suspense fallback={<PageLoader />}><Users /></Suspense></RouteErrorBoundary>} />
                  <Route path="settings" element={<RouteErrorBoundary><Suspense fallback={<PageLoader />}><Settings /></Suspense></RouteErrorBoundary>} />
                </Route>
              </Routes>
            </BrowserRouter>
          </SetupProvider>
        </ToastProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  )
}
