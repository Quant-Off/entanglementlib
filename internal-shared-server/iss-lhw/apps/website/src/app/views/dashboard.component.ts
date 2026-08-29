import { ChangeDetectionStrategy, Component, type OnInit, inject, signal } from "@angular/core";
import { IssApi, describeApiError } from "../core/iss-api.ts";

@Component({
  selector: "app-dashboard",
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="space-y-4">
      <div class="flex items-center gap-3">
        <h2 class="text-lg font-semibold">서버 상태</h2>
        <button
          type="button"
          (click)="refresh()"
          [disabled]="busy()"
          class="rounded-lg border border-ink-700 px-3 py-1 text-xs text-ink-300
                 transition hover:border-accent-600 hover:text-accent-500 disabled:opacity-50"
        >
          새로고침
        </button>
        <button
          type="button"
          (click)="sendPing()"
          [disabled]="busy()"
          class="rounded-lg border border-ink-700 px-3 py-1 text-xs text-ink-300
                 transition hover:border-accent-600 hover:text-accent-500 disabled:opacity-50"
        >
          PING
        </button>
        @if (rtt() !== null) {
          <span class="font-mono text-xs text-accent-500">RTT {{ rtt() }}μs</span>
        }
      </div>

      @if (error() !== null) {
        <p
          class="rounded-lg border border-danger-500/40 bg-danger-500/10 px-3 py-2 text-sm text-danger-500"
        >
          {{ error() }}
        </p>
      }

      @if (statusText() !== null) {
        <pre
          class="overflow-x-auto rounded-xl border border-ink-700 bg-ink-900 p-4 font-mono text-sm
                 leading-relaxed text-ink-100"
          >{{ statusText() }}</pre>
      } @else if (busy()) {
        <p class="text-sm text-ink-500">불러오는 중...</p>
      }
    </section>
  `,
})
export class DashboardComponent implements OnInit {
  private readonly api = inject(IssApi);

  protected readonly statusText = signal<string | null>(null);
  protected readonly rtt = signal<number | null>(null);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);

  ngOnInit(): void {
    void this.refresh();
  }

  protected async refresh(): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    try {
      const response = await this.api.status();
      this.statusText.set(response.status);
    } catch (cause: unknown) {
      this.error.set(describeApiError(cause));
    } finally {
      this.busy.set(false);
    }
  }

  protected async sendPing(): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    try {
      const response = await this.api.ping();
      this.rtt.set(response.rttMicros);
    } catch (cause: unknown) {
      this.error.set(describeApiError(cause));
    } finally {
      this.busy.set(false);
    }
  }
}
