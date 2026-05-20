import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
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
const Alerts = lazy(() => import('./pages/Alerts'))
const SetupKeys = lazy(() => import('./pages/SetupKeys'))
const Users = lazy(() => import('./pages/Users'))
const Settings = lazy(() => import('./pages/Settings'))

function LazyPage({ Component, ...props }) {
  return (
    <RouteErrorBoundary>
      <Suspense fallback={<PageLoader />}>
        <Component {...props} />
      </Suspense>
    </RouteErrorBoundary>
  )
}

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
  if (auth === null) return <PageLoader />
  return auth ? children : <SmartRedirect />
}

function SmartRedirect() {
  const { needsSetup, loading } = useSetup()

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

  // Consolidate needsSetup === null and needsSetup === false — both redirect to /login
  const to = needsSetup ? '/setup' : '/login'
  return <Navigate to={to} replace />
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
                <Route path="/login" element={<LazyPage Component={Login} />} />
        <Route path="/setup" element={<LazyPage Component={Login} mode="setup" />} />
        <Route path="/" element={
          <PrivateRoute>
            <PendingChangesProvider>
              <Layout />
            </PendingChangesProvider>
          </PrivateRoute>
        }>
          <Route index element={<LazyPage Component={Dashboard} />} />
          <Route path="topology" element={<LazyPage Component={Topology} />} />
          <Route path="peers" element={<LazyPage Component={Peers} />} />
          <Route path="groups" element={<LazyPage Component={Groups} />} />
          <Route path="services" element={<LazyPage Component={Services} />} />
          <Route path="policies" element={<LazyPage Component={Policies} />} />
          <Route path="logs" element={<LazyPage Component={Logs} />} />
          <Route path="alerts" element={<LazyPage Component={Alerts} />} />
          <Route path="setup-keys" element={<LazyPage Component={SetupKeys} />} />
          <Route path="users" element={<LazyPage Component={Users} />} />
          <Route path="settings" element={<LazyPage Component={Settings} />} />
                </Route>
              </Routes>
            </BrowserRouter>
          </SetupProvider>
        </ToastProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  )
}
