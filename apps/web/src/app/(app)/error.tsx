"use client";

import { useEffect } from "react";
import { ErrorState } from "@/components/states";

export default function AppError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Surface the error for debugging; replace with telemetry later.
    console.error(error);
  }, [error]);

  return (
    <div className="p-6">
      <ErrorState
        title="This page failed to load"
        message={error.message || "An unexpected error occurred."}
        onRetry={reset}
      />
    </div>
  );
}
