import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'ShadowMesh — Wireshark for AI Agents',
  description: 'Real-time trust scoring, taint propagation, and threat telemetry for multi-agent AI systems.',
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      {/*
        SocketBootstrap removed — useSocket() is now called directly
        inside page.tsx so there is exactly ONE WebSocket connection.
      */}
      <body>{children}</body>
    </html>
  );
}
