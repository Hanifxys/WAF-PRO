import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "export",
  basePath: "/WAF-PRO",
  assetPrefix: "/WAF-PRO",
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
};

export default nextConfig;
