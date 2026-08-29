import { ChangeDetectionStrategy, Component, inject, signal } from "@angular/core";
import { FormsModule } from "@angular/forms";
import { AuthStore } from "../core/auth-store.ts";
import { IssApi, describeApiError } from "../core/iss-api.ts";

@Component({
  selector: "app-token-gate",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule],
  template: `
    <main class="flex min-h-screen items-center justify-center p-6">
      <section class="w-full max-w-md rounded-2xl border border-ink-700 bg-ink-900 p-8 shadow-2xl">
        <header class="mb-6 text-center">
          <p class="font-mono text-xs tracking-[0.3em] text-accent-500">ENTANGLEMENTLIB</p>
          <h1 class="mt-2 text-2xl font-bold">ISS 콘솔</h1>
          <p class="mt-2 text-sm text-ink-300">
            브리지 기동 시 터미널에 출력된 접속 토큰을 입력하세요.
          </p>
        </header>

        <form (ngSubmit)="connect()" class="space-y-4">
          <label class="block">
            <span class="mb-1 block text-xs font-medium text-ink-300">접속 토큰</span>
            <input
              type="password"
              name="token"
              [(ngModel)]="tokenInput"
              autocomplete="off"
              spellcheck="false"
              required
              class="w-full rounded-lg border border-ink-700 bg-ink-950 px-3 py-2 font-mono text-sm
                     text-ink-100 outline-none focus:border-accent-600"
              placeholder="hex 64자"
            />
          </label>

          @if (error() !== null) {
            <p
              class="rounded-lg border border-danger-500/40 bg-danger-500/10 px-3 py-2 text-sm text-danger-500"
            >
              {{ error() }}
            </p>
          }

          <button
            type="submit"
            [disabled]="busy()"
            class="w-full rounded-lg bg-accent-600 px-4 py-2 font-semibold text-ink-950
                   transition hover:bg-accent-500 disabled:opacity-50"
          >
            {{ busy() ? "확인 중" : "연결" }}
          </button>
        </form>

        <p class="mt-6 text-center text-xs text-ink-500">
          토큰은 메모리에만 유지되며 저장되지 않습니다. 새로고침 시 다시 입력해야 합니다.
        </p>
      </section>
    </main>
  `,
})
export class TokenGateComponent {
  private readonly auth = inject(AuthStore);
  private readonly api = inject(IssApi);

  protected tokenInput = "";
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);

  protected async connect(): Promise<void> {
    if (this.busy()) {
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.auth.unlock(this.tokenInput);
    try {
      await this.api.status();
      this.tokenInput = "";
    } catch (cause: unknown) {
      this.auth.lock();
      this.error.set(describeApiError(cause));
    } finally {
      this.busy.set(false);
    }
  }
}
