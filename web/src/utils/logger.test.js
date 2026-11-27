import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

describe('logger', () => {
  let logSpy
  let warnSpy
  let errorSpy

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    // logger captures import.meta.env.DEV at module load, so each test imports
    // a fresh copy after stubbing the environment.
    vi.resetModules()
  })

  afterEach(() => {
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
  })

  test('logs and warns in development', async () => {
    vi.stubEnv('DEV', true)
    vi.resetModules()

    const { logger } = await import('./logger.js')
    logger.log('dev log', 1)
    logger.warn('dev warn', 2)
    logger.error('dev error', 3)

    expect(logSpy).toHaveBeenCalledWith('dev log', 1)
    expect(warnSpy).toHaveBeenCalledWith('dev warn', 2)
    expect(errorSpy).toHaveBeenCalledWith('dev error', 3)
  })

  test('suppresses log and warn outside development', async () => {
    vi.stubEnv('DEV', false)
    vi.resetModules()

    const { logger } = await import('./logger.js')
    logger.log('prod log')
    logger.warn('prod warn')
    logger.error('prod error')

    expect(logSpy).not.toHaveBeenCalled()
    expect(warnSpy).not.toHaveBeenCalled()
    expect(errorSpy).toHaveBeenCalledWith('prod error')
  })
})
