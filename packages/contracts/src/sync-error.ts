export class SyncClientError extends Error {
  constructor(
    readonly code:
      | "invalid_configuration"
      | "invalid_contract"
      | "request_failed"
      | "unauthorized"
      | "forbidden"
      | "not_found"
      | "precondition_failed"
      | "operation_conflict"
      | "invalid_response"
      | "ciphertext_mismatch",
    message: string,
  ) {
    super(message)
    this.name = "SyncClientError"
  }
}
