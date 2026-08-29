import { ChangeDetectionStrategy, Component, inject, signal } from "@angular/core";
import { AuthStore } from "../core/auth-store.ts";
import { DashboardComponent } from "./dashboard.component.ts";
import { KeysComponent } from "./keys.component.ts";

type ConsoleTab = "dashboard" | "keys";

@Component({
  selector: "app-console",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DashboardComponent, KeysComponent],
  template: `
    <div class="mx-auto flex min-h-screen max-w-5xl flex-col px-6 py-6">
      <header class="flex items-center justify-between border-b border-ink-700 pb-4">
        <div class="flex items-baseline gap-3">
          <h1 class="text-xl font-bold">ISS 콘솔</h1>
          <span class="font-mono text-xs text-ink-500">폐쇄망 내부 공유 서버</span>
        </div>
        <button
          type="button"
          (click)="auth.lock()"
          class="rounded-lg border border-ink-700 px-3 py-1.5 text-sm text-ink-300
                 transition hover:border-danger-500 hover:text-danger-500"
        >
          잠금
        </button>
      </header>

      <nav class="mt-4 flex gap-2">
        @for (item of tabs; track item.id) {
          <button
            type="button"
            (click)="tab.set(item.id)"
            [class]="
              tab() === item.id
                ? 'rounded-lg bg-ink-800 px-4 py-2 text-sm font-semibold text-accent-500'
                : 'rounded-lg px-4 py-2 text-sm text-ink-300 transition hover:bg-ink-900'
            "
          >
            {{ item.label }}
          </button>
        }
      </nav>

      <main class="mt-6 flex-1">
        @if (tab() === "dashboard") {
          <app-dashboard />
        } @else {
          <app-keys />
        }
      </main>

      <footer class="mt-8 border-t border-ink-700 pt-4 text-center text-xs text-ink-500">
        루프백 전용 · 값은 명시적 열람 시에만 전송되며 브라우저에 저장되지 않습니다
      </footer>
    </div>
  `,
})
export class ConsoleComponent {
  protected readonly auth = inject(AuthStore);
  protected readonly tab = signal<ConsoleTab>("dashboard");
  protected readonly tabs: readonly { id: ConsoleTab; label: string }[] = [
    { id: "dashboard", label: "대시보드" },
    { id: "keys", label: "키 저장소" },
  ];
}
