/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  // Rewrites act as fallback for any /api/ routes not covered by Route Handlers.
  // Primary API routes (upload, jobs) are handled by Route Handlers in src/app/api/
  // for reliable proxying of POST bodies and explicit error handling.
  async rewrites() {
    const backend = process.env.BACKEND_URL || "http://backend:8000";
    return [
      {
        source: "/api/:path*",
        destination: `${backend}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
