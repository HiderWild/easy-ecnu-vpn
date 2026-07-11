export function errorMessage(error: unknown): string {
  if (typeof error === 'string') return error
  if (error && typeof error === 'object') {
    const anyError = error as {
      code?: string
      message?: string
      response?: { data?: { error?: string; message?: string; code?: string } }
    }
    if (typeof anyError.code === 'string' && anyError.code) return anyError.message || anyError.code
    const responseData = anyError.response?.data
    if (responseData) {
      if (typeof responseData.code === 'string' && responseData.code) return responseData.message || responseData.code
      const responseMessage = responseData.error || responseData.message
      if (responseMessage) return responseMessage
    }
    if (anyError.message) return anyError.message
  }
  return 'Operation failed'
}
