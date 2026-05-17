// ===================
// ©AngelaMos | 2026
// client.ts
// ===================

import axios, { type AxiosInstance, type InternalAxiosRequestConfig } from 'axios'
import type { ZodType } from 'zod'
import { ApiError, ApiErrorCode, transformAxiosError } from '@/core/api'
import { successEnvelope } from './types/error'

const REQUEST_TIMEOUT_MS = 15000
const TURNSTILE_HEADER_NAME = 'CF-Turnstile-Response'

const resolveBaseURL = (): string => {
  const fromEnv = import.meta.env.VITE_API_URL
  if (typeof fromEnv === 'string' && fromEnv.length > 0) {
    return fromEnv
  }
  return '/api'
}

export const apiClient: AxiosInstance = axios.create({
  baseURL: resolveBaseURL(),
  timeout: REQUEST_TIMEOUT_MS,
  headers: { 'Content-Type': 'application/json' },
})

export type TurnstileTokenProvider = () => string | null | undefined

let turnstileProvider: TurnstileTokenProvider | null = null

export function setTurnstileTokenProvider(
  provider: TurnstileTokenProvider | null
): void {
  turnstileProvider = provider
}

apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig): InternalAxiosRequestConfig => {
    const token = turnstileProvider?.()
    if (typeof token === 'string' && token.length > 0) {
      config.headers.set(TURNSTILE_HEADER_NAME, token)
    }
    return config
  }
)

apiClient.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    if (axios.isAxiosError(error)) {
      return Promise.reject(transformAxiosError(error))
    }
    return Promise.reject(error)
  }
)

function unwrapEnvelope<T>(data: unknown, schema: ZodType<T>, status: number): T {
  const parsed = successEnvelope(schema).safeParse(data)
  if (!parsed.success) {
    throw new ApiError(
      'response shape mismatch',
      ApiErrorCode.PARSE_ERROR,
      status
    )
  }
  return parsed.data.data
}

export async function apiGet<T>(path: string, schema: ZodType<T>): Promise<T> {
  const response = await apiClient.get<unknown>(path)
  return unwrapEnvelope(response.data, schema, response.status)
}

export async function apiPost<T>(
  path: string,
  body: unknown,
  schema: ZodType<T>
): Promise<T> {
  const response = await apiClient.post<unknown>(path, body)
  return unwrapEnvelope(response.data, schema, response.status)
}

export async function apiDelete(path: string): Promise<void> {
  await apiClient.delete(path)
}
