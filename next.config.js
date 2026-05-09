/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    serverActions: true,
  },
  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "avatars.githubusercontent.com",
        port: "",
        pathname: "**",
      },
      // Removed: 'tjzk.replicate.delivery', 'replicate.delivery', and 'a16z.com'
      // are NOT in the approved model registry and used wildcard pathnames,
      // violating version pinning and integrity verification requirements.
    ],
  },
};

module.exports = nextConfig;
