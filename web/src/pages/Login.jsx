import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { api } from '../api/client'
import { useAuthStore } from '../store'
import InlineError from '../components/InlineError'

export default function Login() {
  const [isSetup, setIsSetup] = useState(false)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const login = useAuthStore(s => s.login)
  const navigate = useNavigate()

  useEffect(() => {
    // Check if setup is needed
    api.get('/setup').then(() => setIsSetup(true)).catch(() => setIsSetup(false))
  }, [])

  const loginMutation = useMutation({
    mutationFn: () => api.post('/auth/login', { username, password }),
    onSuccess: (data) => {
      login(data.access_token, data.refresh_token)
      navigate('/')
    },
    onError: (err) => setError(err.message),
  })

  const setupMutation = useMutation({
    mutationFn: () => {
      if (password !== confirmPassword) throw new Error('Passwords do not match')
      return api.post('/setup', { username, password })
    },
    onSuccess: (data) => {
      login(data.access_token, data.refresh_token)
      navigate('/')
    },
    onError: (err) => setError(err.message),
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
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-runic-600 dark:text-runic-400">Runic</h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            {isSetup ? 'Welcome — Set up your admin account' : 'Firewall Policy Management'}
          </p>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-8">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                required
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-runic-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-runic-500"
              />
            </div>
            {isSetup && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Confirm Password
                </label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={e => setConfirmPassword(e.target.value)}
                  required
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-runic-500"
                />
              </div>
            )}
            <InlineError message={error} />
            <button
              type="submit"
              disabled={loginMutation.isPending || setupMutation.isPending}
              className="w-full py-2.5 bg-runic-600 hover:bg-runic-700 text-white font-medium rounded-lg disabled:opacity-50"
            >
              {loginMutation.isPending || setupMutation.isPending ? 'Please wait...' : (isSetup ? 'Create Account' : 'Sign In')}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
