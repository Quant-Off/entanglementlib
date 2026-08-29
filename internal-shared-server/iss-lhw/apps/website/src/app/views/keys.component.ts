import { ChangeDetectionStrategy, Component, type OnInit, inject, signal } from "@angular/core";
import { FormsModule } from "@angular/forms";
import { IssApi, describeApiError } from "../core/iss-api.ts";
import { decodeBase64, decodeUtf8Strict, formatBytes, toHexDump } from "../core/value-format.ts";

interface RevealedValue {
  key: string;
  bytes: number;
  text: string | null;
  hexDump: string | null;
  raw: Uint8Array;
}

@Component({
  selector: "app-keys",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule],
  template: `
    <section class="space-y-6">
      <div class="flex items-center gap-3">
        <h2 class="text-lg font-semibold">키 저장소</h2>
        <button
          type="button"
          (click)="refresh()"
          [disabled]="busy()"
          class="rounded-lg border border-ink-700 px-3 py-1 text-xs text-ink-300
                 transition hover:border-accent-600 hover:text-accent-500 disabled:opacity-50"
        >
          새로고침
        </button>
        <span class="text-xs text-ink-500">{{ keys().length }}개 항목</span>
      </div>

      @if (error() !== null) {
        <p
          class="rounded-lg border border-danger-500/40 bg-danger-500/10 px-3 py-2 text-sm text-danger-500"
        >
          {{ error() }}
        </p>
      }

      <form (ngSubmit)="save()" class="space-y-3 rounded-xl border border-ink-700 bg-ink-900 p-4">
        <h3 class="text-sm font-semibold text-ink-300">항목 저장 (신규 또는 덮어쓰기)</h3>
        <div class="flex flex-col gap-3 sm:flex-row">
          <input
            type="text"
            name="newKey"
            [(ngModel)]="newKey"
            autocomplete="off"
            spellcheck="false"
            placeholder="키 이름"
            class="flex-1 rounded-lg border border-ink-700 bg-ink-950 px-3 py-2 font-mono text-sm
                   outline-none focus:border-accent-600"
          />
          <label
            class="cursor-pointer rounded-lg border border-ink-700 px-3 py-2 text-center text-sm
                   text-ink-300 transition hover:border-accent-600"
          >
            {{ fileName() ?? "파일 선택" }}
            <input type="file" class="hidden" (change)="onFile($event)" />
          </label>
        </div>
        <textarea
          name="newValue"
          [(ngModel)]="newValue"
          [disabled]="fileName() !== null"
          rows="3"
          spellcheck="false"
          placeholder="텍스트 값 (파일을 선택하면 파일 내용이 우선합니다)"
          class="w-full rounded-lg border border-ink-700 bg-ink-950 px-3 py-2 font-mono text-sm
                 outline-none focus:border-accent-600 disabled:opacity-40"
        ></textarea>
        <div class="flex items-center gap-3">
          <button
            type="submit"
            [disabled]="busy() || newKey.trim().length === 0"
            class="rounded-lg bg-accent-600 px-4 py-2 text-sm font-semibold text-ink-950
                   transition hover:bg-accent-500 disabled:opacity-50"
          >
            저장
          </button>
          @if (fileName() !== null) {
            <button
              type="button"
              (click)="clearFile()"
              class="text-xs text-ink-500 underline hover:text-ink-300"
            >
              파일 선택 해제
            </button>
          }
          @if (notice() !== null) {
            <span class="text-xs text-accent-500">{{ notice() }}</span>
          }
        </div>
      </form>

      <ul class="divide-y divide-ink-800 rounded-xl border border-ink-700 bg-ink-900">
        @for (key of keys(); track key) {
          <li class="flex items-center justify-between gap-4 px-4 py-3">
            <span class="truncate font-mono text-sm">{{ key }}</span>
            <span class="flex shrink-0 gap-2">
              <button
                type="button"
                (click)="reveal(key)"
                [disabled]="busy()"
                class="rounded-md border border-ink-700 px-2.5 py-1 text-xs text-ink-300
                       transition hover:border-accent-600 hover:text-accent-500 disabled:opacity-50"
              >
                열람
              </button>
              @if (pendingDelete() === key) {
                <button
                  type="button"
                  (click)="remove(key)"
                  [disabled]="busy()"
                  class="rounded-md bg-danger-500 px-2.5 py-1 text-xs font-semibold text-ink-950
                         disabled:opacity-50"
                >
                  삭제 확정
                </button>
                <button
                  type="button"
                  (click)="pendingDelete.set(null)"
                  class="rounded-md border border-ink-700 px-2.5 py-1 text-xs text-ink-300"
                >
                  취소
                </button>
              } @else {
                <button
                  type="button"
                  (click)="pendingDelete.set(key)"
                  [disabled]="busy()"
                  class="rounded-md border border-ink-700 px-2.5 py-1 text-xs text-ink-300
                         transition hover:border-danger-500 hover:text-danger-500 disabled:opacity-50"
                >
                  삭제
                </button>
              }
            </span>
          </li>
        } @empty {
          <li class="px-4 py-6 text-center text-sm text-ink-500">저장된 항목이 없습니다</li>
        }
      </ul>

      @if (revealed() !== null) {
        <section class="space-y-3 rounded-xl border border-warn-500/40 bg-ink-900 p-4">
          <div class="flex items-center justify-between">
            <h3 class="font-mono text-sm font-semibold text-warn-500">
              {{ revealed()!.key }}
              <span class="ml-2 font-normal text-ink-500">{{ formatSize(revealed()!.bytes) }}</span>
            </h3>
            <span class="flex gap-2">
              <button
                type="button"
                (click)="download()"
                class="rounded-md border border-ink-700 px-2.5 py-1 text-xs text-ink-300
                       transition hover:border-accent-600 hover:text-accent-500"
              >
                다운로드
              </button>
              <button
                type="button"
                (click)="closeReveal()"
                class="rounded-md bg-ink-700 px-2.5 py-1 text-xs font-semibold text-ink-100"
              >
                닫기
              </button>
            </span>
          </div>
          <pre
            class="max-h-80 overflow-auto rounded-lg border border-ink-800 bg-ink-950 p-3 font-mono
                   text-xs leading-relaxed"
            >{{ revealed()!.text ?? revealed()!.hexDump }}</pre>
          <p class="text-xs text-ink-500">
            이 값은 화면에만 표시되며 닫으면 폐기됩니다. 브라우저에 저장되지 않습니다.
          </p>
        </section>
      }
    </section>
  `,
})
export class KeysComponent implements OnInit {
  private readonly api = inject(IssApi);

  protected readonly keys = signal<readonly string[]>([]);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly pendingDelete = signal<string | null>(null);
  protected readonly revealed = signal<RevealedValue | null>(null);
  protected readonly fileName = signal<string | null>(null);

  protected newKey = "";
  protected newValue = "";
  private fileBytes: Uint8Array | null = null;

  ngOnInit(): void {
    void this.refresh();
  }

  protected formatSize(bytes: number): string {
    return formatBytes(bytes);
  }

  protected async refresh(): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    try {
      const response = await this.api.keys();
      this.keys.set(response.keys);
    } catch (cause: unknown) {
      this.error.set(describeApiError(cause));
    } finally {
      this.busy.set(false);
    }
  }

  protected onFile(event: Event): void {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (file === undefined) {
      return;
    }
    void file.arrayBuffer().then((buffer) => {
      this.fileBytes = new Uint8Array(buffer);
      this.fileName.set(file.name);
    });
    input.value = "";
  }

  protected clearFile(): void {
    this.fileBytes = null;
    this.fileName.set(null);
  }

  protected async save(): Promise<void> {
    const key = this.newKey.trim();
    if (key.length === 0 || this.busy()) {
      return;
    }
    const value = this.fileBytes ?? new TextEncoder().encode(this.newValue);
    if (value.length === 0) {
      this.error.set("값이 비어 있습니다. 텍스트를 입력하거나 파일을 선택하세요.");
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.notice.set(null);
    try {
      await this.api.putValue(key, value);
      this.notice.set(`'${key}' 저장 완료`);
      this.newKey = "";
      this.newValue = "";
      this.clearFile();
      await this.refresh();
    } catch (cause: unknown) {
      this.error.set(describeApiError(cause));
    } finally {
      this.busy.set(false);
    }
  }

  protected async reveal(key: string): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    try {
      const response = await this.api.revealValue(key);
      const raw = decodeBase64(response.valueBase64);
      const text = decodeUtf8Strict(raw);
      this.revealed.set({
        key: response.key,
        bytes: response.bytes,
        text,
        hexDump: text === null ? toHexDump(raw) : null,
        raw,
      });
    } catch (cause: unknown) {
      this.error.set(describeApiError(cause));
    } finally {
      this.busy.set(false);
    }
  }

  protected closeReveal(): void {
    const current = this.revealed();
    if (current !== null) {
      current.raw.fill(0);
    }
    this.revealed.set(null);
  }

  protected download(): void {
    const current = this.revealed();
    if (current === null) {
      return;
    }
    const blob = new Blob([current.raw.slice().buffer as ArrayBuffer], {
      type: "application/octet-stream",
    });
    const url = URL.createObjectURL(blob);
    try {
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = current.key;
      anchor.click();
    } finally {
      setTimeout(() => {
        URL.revokeObjectURL(url);
      }, 1000);
    }
  }

  protected async remove(key: string): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    try {
      await this.api.deleteKey(key);
      this.pendingDelete.set(null);
      if (this.revealed()?.key === key) {
        this.closeReveal();
      }
      await this.refresh();
    } catch (cause: unknown) {
      this.error.set(describeApiError(cause));
    } finally {
      this.busy.set(false);
    }
  }
}
