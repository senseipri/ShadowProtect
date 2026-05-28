'use client';

import { useSocket } from '@/lib/useSocket';

export default function SocketBootstrap(): null {
  useSocket();
  return null;
}
