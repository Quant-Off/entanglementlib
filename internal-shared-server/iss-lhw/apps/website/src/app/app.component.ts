import { ChangeDetectionStrategy, Component, inject } from "@angular/core";
import { AuthStore } from "./core/auth-store.ts";
import { ConsoleComponent } from "./views/console.component.ts";
import { TokenGateComponent } from "./views/token-gate.component.ts";

@Component({
  selector: "app-root",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TokenGateComponent, ConsoleComponent],
  template: `
    @if (auth.token() === null) {
      <app-token-gate />
    } @else {
      <app-console />
    }
  `,
})
export class AppComponent {
  protected readonly auth = inject(AuthStore);
}
