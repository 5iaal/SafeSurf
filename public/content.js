/* global chrome */
function safeText(el) {
  return (el?.innerText || el?.textContent || "").trim();
}

function collectPageSignals() {
  const title = document.title || "";
  const text = (document.body?.innerText || "").slice(0, 3000);
  const hasPasswordForm = !!document.querySelector('input[type="password"]');
  const links = Array.from(document.querySelectorAll("a[href]"))
    .map((a) => a.href)
    .filter((h) => h.startsWith("http"));
  return { title, textSample: text, hasPasswordForm, linkCount: links.length };
}

function isGmail() {
  return location.hostname.includes("mail.google.com");
}

/**
 * Gmail open email extraction (best-effort)
 * Works when a message is opened (not just inbox list).
 */
function collectGmailOpenEmail() {
  // Sender
  // Common: span.gD or span.go
  const senderEl = document.querySelector("span.gD, span.go");
  const sender = safeText(senderEl);

  // Subject
  // Common: h2.hP
  const subjectEl = document.querySelector("h2.hP");
  const subject = safeText(subjectEl);

  // Body
  // Common: div.a3s (email body container)
  const bodyEl = document.querySelector("div.a3s");
  const body = safeText(bodyEl);

  return { sender, subject, body };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "GET_PAGE_SIGNALS") {
    sendResponse({ signals: collectPageSignals() });
    return;
  }

  if (msg?.type === "GET_OPEN_EMAIL") {
    if (!isGmail()) {
      sendResponse({ provider: "unknown", email: { sender: "", subject: "", body: "" } });
      return;
    }

    const email = collectGmailOpenEmail();
    sendResponse({ provider: "gmail", email });
    return;
  }
});
