// Service worker for FBC Reservation SMS PWA. Handles Web Push delivery and
// click-through routing. No offline caching — the dashboard is online-only.

self.addEventListener("install", (event) => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = { title: "New message", body: event.data ? event.data.text() : "" };
  }
  const title = data.title || "New SMS";
  const body = data.body || "";
  const url = data.url || "/dashboard";

  event.waitUntil((async () => {
    // If a dashboard tab is already open and visible, hand off to it for a
    // softer in-tab toast and skip the OS banner. Otherwise, show the OS push.
    const clientsList = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    const visibleClient = clientsList.find((c) => c.visibilityState === "visible");
    if (visibleClient) {
      visibleClient.postMessage({ type: "sms-inbound", title, body, url, phone: data.phone || null });
      return;
    }
    await self.registration.showNotification(title, {
      body,
      tag: data.phone ? `sms-${data.phone}` : undefined,
      renotify: true,
      data: { url, phone: data.phone || null },
      icon: "/icons/icon.svg",
      badge: "/icons/icon.svg",
    });
    // Also wake any background tabs so they can refresh their conversation list.
    for (const c of clientsList) {
      c.postMessage({ type: "sms-inbound", title, body, url, phone: data.phone || null, background: true });
    }
  })());
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || "/dashboard";
  event.waitUntil((async () => {
    const clientsList = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of clientsList) {
      if ("focus" in c) {
        c.postMessage({ type: "open-conversation", url, phone: event.notification.data && event.notification.data.phone });
        return c.focus();
      }
    }
    if (self.clients.openWindow) return self.clients.openWindow(url);
  })());
});
