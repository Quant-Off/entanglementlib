import { HttpClient, HttpErrorResponse, HttpHeaders } from "@angular/common/http";
import { Injectable, inject } from "@angular/core";
import { firstValueFrom } from "rxjs";

export interface StatusResponse {
  status: string;
}

export interface PingResponse {
  ok: boolean;
  rttMicros: number;
}

export interface KeysResponse {
  keys: string[];
}

export interface ValueResponse {
  key: string;
  bytes: number;
  valueBase64: string;
}

export function describeApiError(error: unknown): string {
  if (error instanceof HttpErrorResponse) {
    const body: unknown = error.error;
    if (typeof body === "object" && body !== null && "error" in body) {
      const message = (body as Record<string, unknown>)["error"];
      if (typeof message === "string" && message.length > 0) {
        return message;
      }
    }
    if (error.status === 0) {
      return "브리지에 연결할 수 없습니다";
    }
    return `요청 실패 (HTTP ${String(error.status)})`;
  }
  return "알 수 없는 오류가 발생했습니다";
}

@Injectable({ providedIn: "root" })
export class IssApi {
  private readonly http = inject(HttpClient);

  status(): Promise<StatusResponse> {
    return firstValueFrom(this.http.get<StatusResponse>("/api/status"));
  }

  ping(): Promise<PingResponse> {
    return firstValueFrom(this.http.get<PingResponse>("/api/ping"));
  }

  keys(): Promise<KeysResponse> {
    return firstValueFrom(this.http.get<KeysResponse>("/api/keys"));
  }

  revealValue(key: string): Promise<ValueResponse> {
    return firstValueFrom(
      this.http.get<ValueResponse>(`/api/keys/${encodeURIComponent(key)}/value`),
    );
  }

  putValue(key: string, value: Uint8Array): Promise<void> {
    const body = value.slice().buffer as ArrayBuffer;
    return firstValueFrom(
      this.http.put(`/api/keys/${encodeURIComponent(key)}`, body, {
        headers: new HttpHeaders({ "Content-Type": "application/octet-stream" }),
      }),
    ).then(() => undefined);
  }

  deleteKey(key: string): Promise<void> {
    return firstValueFrom(this.http.delete(`/api/keys/${encodeURIComponent(key)}`)).then(
      () => undefined,
    );
  }
}
