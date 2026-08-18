export class ApiError extends Error {
  public code: string;
  public status: number;
  public requestId?: string;
  public details?: any;

  constructor(
    message: string,
    status: number,
    code: string = 'UNKNOWN_ERROR',
    requestId?: string,
    details?: any
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.details = details;
  }
}
