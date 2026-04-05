function apiBaseUrl() {
  return import.meta.env.VITE_API_URL ?? "";
}

export function wsBaseUrl() {
  if (import.meta.env.VITE_WS_URL) {
    return import.meta.env.VITE_WS_URL as string;
  }

  const url = new URL(apiBaseUrl() || window.location.origin);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/api/v1/ws";
  url.search = "";
  return url.toString();
}

export async function createSession(sessionId: string) {
  const response = await fetch(`${apiBaseUrl()}/api/v1/sessions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ sessionId })
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || "failed to create session");
  }

  return (await response.json()) as {
    sessionId: string;
    expiresInSeconds: number;
  };
}
