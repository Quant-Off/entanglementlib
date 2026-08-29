import { Injectable, signal } from "@angular/core";

@Injectable({ providedIn: "root" })
export class AuthStore {
  private readonly tokenState = signal<string | null>(null);

  readonly token = this.tokenState.asReadonly();

  unlock(token: string): void {
    const trimmed = token.trim();
    this.tokenState.set(trimmed.length > 0 ? trimmed : null);
  }

  lock(): void {
    this.tokenState.set(null);
  }
}
