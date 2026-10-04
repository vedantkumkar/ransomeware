import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"
import type { TimelineEvent } from "@/types"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * Total elapsed seconds covered by a response timeline
 * (timestamps formatted as "HH:MM:SS.mmm"), or null if not computable.
 */
export function computeResponseSeconds(timeline: TimelineEvent[]): number | null {
  if (timeline.length < 2) return null;
  const toSeconds = (timestamp: string): number => {
    const parts = timestamp.split(":").map(Number);
    if (parts.length < 3 || parts.some((n) => Number.isNaN(n))) return NaN;
    return parts[0] * 3600 + parts[1] * 60 + parts[2];
  };
  const start = toSeconds(timeline[0].timestamp);
  const end = toSeconds(timeline[timeline.length - 1].timestamp);
  if (Number.isNaN(start) || Number.isNaN(end)) return null;
  return Math.max(0, end - start);
}
