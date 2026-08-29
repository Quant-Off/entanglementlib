import "./styles.css";
import { provideHttpClient, withInterceptors } from "@angular/common/http";
import { provideZonelessChangeDetection } from "@angular/core";
import { bootstrapApplication } from "@angular/platform-browser";
import { AppComponent } from "./app/app.component.ts";
import { authInterceptor } from "./app/core/auth.interceptor.ts";

bootstrapApplication(AppComponent, {
  providers: [
    provideZonelessChangeDetection(),
    provideHttpClient(withInterceptors([authInterceptor])),
  ],
}).catch((error: unknown) => {
  console.error("부트스트랩 실패", error);
});
