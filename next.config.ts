import type { NextConfig } from "next";

const dev = process.env.NODE_ENV !== "production";
const scriptSrc = `script-src 'self' 'unsafe-inline'${dev ? " 'unsafe-eval'" : ""}`;

const nextConfig: NextConfig = {
  output: "standalone",
  serverExternalPackages: ["postgres", "@azure/identity"],
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "Content-Security-Policy", value: `default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; ${scriptSrc}; connect-src 'self'${dev ? " ws: wss:" : ""}; frame-ancestors 'none'` },
        ],
      },
    ];
  },
};

export default nextConfig;
