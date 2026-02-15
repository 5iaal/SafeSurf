/* global chrome */

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "GET_ACTIVE_TAB") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs?.[0];
      sendResponse({ url: tab?.url || "" });
    });
    return true; // مهم عشان async response
  }
});
