const RAW = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8082";

export const API = RAW.replace(/\/$/, "");

export async function apiFetch(path: string, init?: RequestInit) {
  const res = await fetch(`${API}${path}`, init);
  if (!res.ok) {
    throw new Error(`API ${path} -> ${res.status} ${res.statusText}`);
  }
  const text = await res.text();
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    return text;
  }
}