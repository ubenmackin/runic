import { Loader2 } from "lucide-react";

export default function FetchStep({ fetchStatus }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-4">
      <Loader2 className="w-12 h-12 text-blue-500 animate-spin" />
      <p className="text-lg text-gray-600 dark:text-gray-300">
        {fetchStatus === "initiating" &&
          "Sending request to agent..."}
        {fetchStatus === "pending" &&
          "Waiting for agent to send backup..."}
        {fetchStatus === "parsed" &&
          "Rules parsed! Loading review..."}
      </p>
      <p className="text-sm text-gray-400">
        This may take a few seconds
      </p>
    </div>
  );
}
