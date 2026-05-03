import type { CapacitorConfig } from "@capacitor/cli";

const config: CapacitorConfig = {
  appId: "com.web2fa.local",
  appName: "Web 2FA Authenticator",
  webDir: "dist-local",
  server: {
    hostname: "localhost",
    androidScheme: "https",
  },
};

export default config;
