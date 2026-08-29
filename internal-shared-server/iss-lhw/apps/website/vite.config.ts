import angular from "@analogjs/vite-plugin-angular";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite-plus";

const bridgePort = process.env["LHW_PORT"] ?? "5874";

export default defineConfig({
  plugins: [angular(), tailwindcss()],
  server: {
    host: "127.0.0.1",
    proxy: {
      "/api": {
        target: `http://127.0.0.1:${bridgePort}`,
      },
    },
  },
});
