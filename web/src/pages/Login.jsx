import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { api } from '../api/client'
import { useAuthStore } from '../store'
import { useSetup } from '../contexts/SetupContext'
import InlineError from '../components/InlineError'

export default function Login({ mode }) {
  const { needsSetup, loading } = useSetup()
  const [isSetup, setIsSetup] = useState(mode === 'setup')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const login = useAuthStore(s => s.login)
  const navigate = useNavigate()

  useEffect(() => {
    if (loading) return // Wait for context state

    // Handle edge cases:
    // - If mode="setup" but setup is already done, redirect to /login
    // - If mode is undefined but setup is needed, update state
    if (mode === 'setup' && !needsSetup) {
      navigate('/login', { replace: true })
    } else if (mode === undefined && needsSetup !== null) {
      setIsSetup(needsSetup)
    }
  }, [mode, needsSetup, loading, navigate])

  const loginMutation = useMutation({
    mutationFn: () => api.post('/auth/login', { username, password }),
    onSuccess: async () => {
      await login()
      if (useAuthStore.getState().isAuthenticated) {
        navigate('/')
      } else {
        setError('Login succeeded but session verification failed. Please try again.')
      }
    },
    onError: (err) => setError(err.message),
  })

  const setupMutation = useMutation({
    mutationFn: () => {
      if (password !== confirmPassword) throw new Error('Passwords do not match')
      return api.post('/setup', { username, password })
    },
    onSuccess: async () => {
      await login()
      if (useAuthStore.getState().isAuthenticated) {
        navigate('/')
      } else {
        setError('Setup succeeded but session verification failed. Please try again.')
      }
    },
    onError: (err) => {
      setError(err.message)
      // If setup is already completed (403 error), redirect to login
      if (err.message.includes('Setup already completed')) {
        // Reset setup mode and let the user log in
        setIsSetup(false)
      }
    },
  })

  const handleSubmit = (e) => {
    e.preventDefault()
    setError('')
    if (isSetup) {
      setupMutation.mutate()
    } else {
      loginMutation.mutate()
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-charcoal-darkest flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-runic-600 dark:text-purple-active">Runic</h1>
          <p className="text-gray-500 dark:text-amber-muted mt-1">
            {isSetup ? 'Welcome — Set up your admin account' : 'Firewall Policy Management'}
          </p>
        </div>
        <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none p-8">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
<label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
				Username
			</label>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                required
className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-runic-500"
        />
			</div>
			<div>
				<label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
				Password
              </label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-runic-500"
        />
			</div>
			{isSetup && (
				<div>
				<label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
				Confirm Password
                </label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={e => setConfirmPassword(e.target.value)}
                  required
className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-runic-500"
        />
              </div>
            )}
            <InlineError message={error} />
            <button
              type="submit"
              disabled={loginMutation.isPending || setupMutation.isPending}
              className="w-full py-2.5 bg-purple-active hover:bg-purple-600 text-white font-bold uppercase rounded-none disabled:opacity-50 border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all"
            >
              {loginMutation.isPending || setupMutation.isPending ? 'Please wait...' : (isSetup ? 'Create Account' : 'Sign In')}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
