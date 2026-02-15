import React, { useEffect, useState } from "react";
import axios from "axios";
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Wifi,
  Mail,
  Search,
  Loader,
  Flag,
  ThumbsUp,
  ThumbsDown,
  Check,
  Settings,
} from "lucide-react";

const API_ANALYZE_URL = "http://127.0.0.1:8000/analyze-url";
const API_ANALYZE_EMAIL = "http://127.0.0.1:8000/analyze-email";

const App = () => {
  const [mode, setMode] = useState("url"); // 'url' | 'email'

  // ---------------------------
  // URL MODE (Separated)
  // ---------------------------
  const [currentUrl, setCurrentUrl] = useState("");
  const [urlRiskScore, setUrlRiskScore] = useState(0);
  const [urlStatus, setUrlStatus] = useState("safe");
  const [urlReasons, setUrlReasons] = useState([]);
  const [isUrlAnalyzing, setIsUrlAnalyzing] = useState(false);

  // URL Sandbox (Separated)
  const [urlSandboxInput, setUrlSandboxInput] = useState("");
  const [urlSandboxResult, setUrlSandboxResult] = useState(null);
  const [isUrlSandboxAnalyzing, setIsUrlSandboxAnalyzing] = useState(false);

  // ---------------------------
  // EMAIL MODE (Separated)
  // ---------------------------
  const [emailSender, setEmailSender] = useState("");
  const [emailSubject, setEmailSubject] = useState("");
  const [emailBodyPreview, setEmailBodyPreview] = useState("");

  const [emailRiskScore, setEmailRiskScore] = useState(0);
  const [emailStatus, setEmailStatus] = useState("safe");
  const [emailReasons, setEmailReasons] = useState([]);
  const [isEmailAnalyzing, setIsEmailAnalyzing] = useState(false);

  // Email Sandbox (Separated)
  const [emailSandboxSender, setEmailSandboxSender] = useState("");
  const [emailSandboxSubject, setEmailSandboxSubject] = useState("");
  const [emailSandboxBody, setEmailSandboxBody] = useState("");
  const [emailSandboxResult, setEmailSandboxResult] = useState(null);
  const [isEmailSandboxAnalyzing, setIsEmailSandboxAnalyzing] = useState(false);

  // ---------------------------
  // Reporting (UI-only for now)
  // ---------------------------
  const [reportSubmitted, setReportSubmitted] = useState(false);
  const [reportType, setReportType] = useState(null);

  // ---------------------------
  // Helpers
  // ---------------------------
  const isChromeExt = () => typeof chrome !== "undefined" && chrome?.runtime?.sendMessage;

  const getStatusInfo = (status) => {
    switch (status) {
      case "high_risk":
        return { color: "bg-red-500", text: "Phishing Detected", icon: AlertTriangle };
      case "low_risk":
        return { color: "bg-yellow-500", text: "Suspicious", icon: Shield };
      case "safe":
        return { color: "bg-green-500", text: "Safe", icon: CheckCircle };
      default:
        return { color: "bg-blue-500", text: "Analyzing", icon: Shield };
    }
  };

  // ---------------------------
  // URL: Fetch Active Tab URL
  // ---------------------------
  const fetchActiveTabUrl = () => {
    if (!isChromeExt()) return;

    chrome.runtime.sendMessage({ type: "GET_ACTIVE_TAB" }, (res) => {
      if (chrome.runtime.lastError) {
        console.warn("GET_ACTIVE_TAB error:", chrome.runtime.lastError.message);
        return;
      }
      if (res?.url) setCurrentUrl(res.url);
    });
  };

  // ---------------------------
  // EMAIL: Read open email from page (Gmail)
  // ---------------------------
  const fetchOpenEmailFromPage = () => {
    if (!isChromeExt() || !chrome?.tabs?.query || !chrome?.tabs?.sendMessage) return;

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs?.[0]?.id;
      if (!tabId) return;

      chrome.tabs.sendMessage(tabId, { type: "GET_OPEN_EMAIL" }, (res) => {
        if (chrome.runtime.lastError) {
          console.warn("GET_OPEN_EMAIL error:", chrome.runtime.lastError.message);
          return;
        }

        const e = res?.email || {};
        if (e.sender || e.subject || e.body) {
          setEmailSender(e.sender || "");
          setEmailSubject(e.subject || "");
          setEmailBodyPreview(e.body || "");

          // كمان نخلي Email sandbox تمشي بنفس البيانات كبداية
          setEmailSandboxSender(e.sender || "");
          setEmailSandboxSubject(e.subject || "");
          setEmailSandboxBody(e.body || "");
        }
      });
    });
  };

  // أول ما popup يفتح: هات URL
  useEffect(() => {
    fetchActiveTabUrl();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // لما تدخل Email mode: اقرأ الإيميل المفتوح تلقائيًا
  useEffect(() => {
    if (mode !== "email") return;
    fetchOpenEmailFromPage();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode]);

  // ---------------------------
  // URL: Analyze current URL (auto)
  // ---------------------------
  const analyzeCurrentUrl = async (url) => {
    try {
      setIsUrlAnalyzing(true);
      const response = await axios.post(API_ANALYZE_URL, { url: url || "" });

      setUrlRiskScore(typeof response.data.riskScore === "number" ? response.data.riskScore : 0);
      setUrlStatus(response.data.status || "safe");
      setUrlReasons(Array.isArray(response.data.reasons) ? response.data.reasons : []);
    } catch (err) {
      console.error("URL analysis failed:", err);
      setUrlRiskScore(0);
      setUrlStatus("safe");
      setUrlReasons([]);
    } finally {
      setIsUrlAnalyzing(false);
    }
  };

  useEffect(() => {
    if (mode !== "url") return;
    if (!currentUrl) return;
    analyzeCurrentUrl(currentUrl);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, currentUrl]);

  // ---------------------------
  // EMAIL: Analyze opened email (auto)
  // ---------------------------
  const analyzeCurrentEmail = async (sender, subject, body) => {
    try {
      setIsEmailAnalyzing(true);

      const response = await axios.post(API_ANALYZE_EMAIL, {
        sender: sender || "",
        subject: subject || "",
        body: body || "",
      });

      setEmailRiskScore(typeof response.data.riskScore === "number" ? response.data.riskScore : 0);
      setEmailStatus(response.data.status || "safe");
      setEmailReasons(Array.isArray(response.data.reasons) ? response.data.reasons : []);
    } catch (err) {
      console.error("Email analysis failed:", err);
      setEmailRiskScore(0);
      setEmailStatus("safe");
      setEmailReasons([]);
    } finally {
      setIsEmailAnalyzing(false);
    }
  };

  useEffect(() => {
    if (mode !== "email") return;

    // لو لسه مفيش بيانات مقروءة من الصفحة، ما تحللش
    if (!emailSender && !emailSubject && !emailBodyPreview) return;

    analyzeCurrentEmail(emailSender, emailSubject, emailBodyPreview);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, emailSender, emailSubject, emailBodyPreview]);

  // ---------------------------
  // URL Sandbox
  // ---------------------------
  const analyzeUrlSandbox = async () => {
    if (!urlSandboxInput.trim()) return;

    setIsUrlSandboxAnalyzing(true);
    setUrlSandboxResult(null);

    try {
      const response = await axios.post(API_ANALYZE_URL, { url: urlSandboxInput.trim() });

      setUrlSandboxResult({
        input: urlSandboxInput.trim(),
        status: response.data.status,
        riskScore: response.data.riskScore,
        reasons: Array.isArray(response.data.reasons) ? response.data.reasons : [],
      });
    } catch (err) {
      console.error("URL sandbox analysis failed:", err);
    } finally {
      setIsUrlSandboxAnalyzing(false);
    }
  };

  // ---------------------------
  // Email Sandbox
  // ---------------------------
  const analyzeEmailSandbox = async () => {
    const s = (emailSandboxSender || "").trim();
    const sub = (emailSandboxSubject || "").trim();
    const b = (emailSandboxBody || "").trim();
    if (!s && !sub && !b) return;

    setIsEmailSandboxAnalyzing(true);
    setEmailSandboxResult(null);

    try {
      const response = await axios.post(API_ANALYZE_EMAIL, {
        sender: s,
        subject: sub,
        body: b,
      });

      setEmailSandboxResult({
        sender: s,
        subject: sub,
        body: b,
        status: response.data.status,
        riskScore: response.data.riskScore,
        reasons: Array.isArray(response.data.reasons) ? response.data.reasons : [],
      });
    } catch (err) {
      console.error("Email sandbox analysis failed:", err);
    } finally {
      setIsEmailSandboxAnalyzing(false);
    }
  };

  // ---------------------------
  // Report (UI-only)
  // ---------------------------
  const handleReport = (type) => {
    setReportType(type);
    setReportSubmitted(true);
    setTimeout(() => setReportSubmitted(false), 2000);
  };

  // ---------------------------
  // Render helpers
  // ---------------------------
  const renderReasons = (reasons) => {
    if (!reasons || reasons.length === 0) return null;

    return (
      <div className="mt-3 text-left bg-gray-50 border rounded p-2">
        <p className="text-xs font-semibold text-gray-700 mb-1">Why?</p>
        <ul className="list-disc pl-4 space-y-1">
          {reasons.slice(0, 6).map((reason, index) => (
            <li key={index} className="text-xs text-gray-600">
              {reason}
            </li>
          ))}
        </ul>
      </div>
    );
  };

  const currentStatus = mode === "url" ? urlStatus : emailStatus;
  const currentRisk = mode === "url" ? urlRiskScore : emailRiskScore;
  const currentReasons = mode === "url" ? urlReasons : emailReasons;
  const currentLoading = mode === "url" ? isUrlAnalyzing : isEmailAnalyzing;

  const StatusIcon = getStatusInfo(currentStatus).icon;

  return (
    <div className="w-80 min-h-[600px] bg-white shadow-lg rounded-lg overflow-hidden">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-600 to-purple-600 p-4 text-white">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Shield className="w-5 h-5" />
            <span className="font-semibold">SafeSurf</span>
          </div>
          <Settings className="w-4 h-4 opacity-75" />
        </div>
        <p className="text-xs opacity-90 mt-1">Real-time phishing protection</p>
      </div>

      {/* Mode Switch */}
      <div className="p-3 bg-gray-50 border-b">
        <div className="flex bg-white rounded-lg p-1">
          <button
            onClick={() => setMode("url")}
            className={`flex-1 flex items-center justify-center space-x-1 py-1.5 px-2 text-xs font-medium rounded transition-colors ${
              mode === "url" ? "bg-blue-600 text-white" : "text-gray-600 hover:text-gray-800"
            }`}
          >
            <Wifi className="w-3 h-3" />
            <span>URL</span>
          </button>
          <button
            onClick={() => setMode("email")}
            className={`flex-1 flex items-center justify-center space-x-1 py-1.5 px-2 text-xs font-medium rounded transition-colors ${
              mode === "email" ? "bg-blue-600 text-white" : "text-gray-600 hover:text-gray-800"
            }`}
          >
            <Mail className="w-3 h-3" />
            <span>Email</span>
          </button>
        </div>
      </div>

      {/* Current Content */}
      <div className="p-4 border-b">
        {mode === "url" ? (
          <>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center space-x-2">
                <Wifi className="w-4 h-4 text-gray-500" />
                <span className="text-xs text-gray-500">Current page:</span>
              </div>
              <button
                onClick={fetchActiveTabUrl}
                className="text-xs px-2 py-1 rounded border bg-white hover:bg-gray-50 text-gray-700"
              >
                Refresh
              </button>
            </div>
            <p className="text-sm font-mono text-gray-800 bg-gray-50 p-2 rounded break-all">
              {currentUrl || "No active URL yet (load extension in Chrome)."}
            </p>
          </>
        ) : (
          <>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center space-x-2">
                <Mail className="w-4 h-4 text-gray-500" />
                <span className="text-xs text-gray-500">Opened email (Gmail):</span>
              </div>

              <button
                onClick={fetchOpenEmailFromPage}
                className="text-xs px-2 py-1 rounded border bg-white hover:bg-gray-50 text-gray-700"
              >
                Read Open Email
              </button>
            </div>

            <div className="space-y-2">
              <div className="bg-gray-50 p-2 rounded">
                <p className="text-xs font-medium text-gray-700 break-all">From:</p>
                <input
                  value={emailSender}
                  onChange={(e) => setEmailSender(e.target.value)}
                  className="w-full mt-1 text-xs p-2 border border-gray-300 rounded"
                  placeholder="(Will auto-fill from open Gmail email)"
                />

                <p className="text-xs font-medium text-gray-700 break-all mt-2">Subject:</p>
                <input
                  value={emailSubject}
                  onChange={(e) => setEmailSubject(e.target.value)}
                  className="w-full mt-1 text-xs p-2 border border-gray-300 rounded"
                  placeholder="(Will auto-fill)"
                />
              </div>

              <div className="bg-gray-50 p-2 rounded">
                <p className="text-xs font-medium text-gray-700">Body preview:</p>
                <textarea
                  value={emailBodyPreview}
                  onChange={(e) => setEmailBodyPreview(e.target.value)}
                  className="w-full mt-1 text-xs p-2 border border-gray-300 rounded min-h-[64px]"
                  placeholder="(Will auto-fill from the open email body)"
                />
              </div>

              <p className="text-[11px] text-gray-500">
                Tip: افتح رسالة داخل Gmail (مش Inbox list بس) وبعدين اضغط Read Open Email.
              </p>
            </div>
          </>
        )}
      </div>

      {/* Risk Status */}
      <div className="p-4 text-center">
        {currentLoading ? (
          <div className="py-4">
            <Loader className="w-5 h-5 text-blue-600 animate-spin mx-auto mb-2" />
            <p className="text-sm text-gray-600">Analyzing...</p>
          </div>
        ) : (
          <>
            <div
              className={`inline-flex items-center justify-center w-12 h-12 ${getStatusInfo(currentStatus).color} rounded-full mb-3`}
            >
              <StatusIcon className="w-6 h-6 text-white" />
            </div>
            <p className="font-semibold text-gray-900 mb-1">{getStatusInfo(currentStatus).text}</p>
            <p className="text-sm text-gray-600">Risk: {(currentRisk * 100).toFixed(0)}%</p>
            {renderReasons(currentReasons)}
          </>
        )}
      </div>

      {/* Sandbox (Separated per mode) */}
      <div className="p-4 border-t bg-gray-50">
        <div className="flex items-center space-x-2 mb-3">
          <Search className="w-4 h-4 text-gray-600" />
          <span className="text-sm font-medium">{mode === "url" ? "URL Sandbox Test" : "Email Sandbox Test"}</span>
        </div>

        {mode === "url" ? (
          <>
            <div className="flex space-x-2 mb-3">
              <input
                type="text"
                value={urlSandboxInput}
                onChange={(e) => setUrlSandboxInput(e.target.value)}
                placeholder="Enter URL to test"
                className="flex-1 text-xs p-2 border border-gray-300 rounded focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
                onKeyDown={(e) => e.key === "Enter" && analyzeUrlSandbox()}
              />
              <button
                onClick={analyzeUrlSandbox}
                disabled={isUrlSandboxAnalyzing || !urlSandboxInput.trim()}
                className="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white p-2 rounded transition-colors"
              >
                {isUrlSandboxAnalyzing ? <Loader className="w-3 h-3 animate-spin" /> : <Search className="w-3 h-3" />}
              </button>
            </div>

            {urlSandboxResult && (
              <div className="p-3 rounded border bg-white">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-medium text-gray-800">{getStatusInfo(urlSandboxResult.status).text}</span>
                  <span className="text-xs font-bold text-gray-800">{(urlSandboxResult.riskScore * 100).toFixed(0)}%</span>
                </div>
                <p className="text-xs text-gray-600 mb-2 break-all">{urlSandboxResult.input}</p>
                {renderReasons(urlSandboxResult.reasons)}
              </div>
            )}
          </>
        ) : (
          <>
            <div className="space-y-2 mb-3">
              <input
                type="text"
                value={emailSandboxSender}
                onChange={(e) => setEmailSandboxSender(e.target.value)}
                placeholder="Sender (e.g. support@company.com)"
                className="w-full text-xs p-2 border border-gray-300 rounded"
              />
              <input
                type="text"
                value={emailSandboxSubject}
                onChange={(e) => setEmailSandboxSubject(e.target.value)}
                placeholder="Subject"
                className="w-full text-xs p-2 border border-gray-300 rounded"
              />
              <textarea
                value={emailSandboxBody}
                onChange={(e) => setEmailSandboxBody(e.target.value)}
                placeholder="Email body"
                className="w-full text-xs p-2 border border-gray-300 rounded min-h-[70px]"
              />
              <button
                onClick={analyzeEmailSandbox}
                disabled={
                  isEmailSandboxAnalyzing ||
                  (!emailSandboxSender.trim() && !emailSandboxSubject.trim() && !emailSandboxBody.trim())
                }
                className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white p-2 rounded transition-colors text-xs flex items-center justify-center gap-2"
              >
                {isEmailSandboxAnalyzing ? <Loader className="w-3 h-3 animate-spin" /> : <Search className="w-3 h-3" />}
                Analyze Email
              </button>
            </div>

            {emailSandboxResult && (
              <div className="p-3 rounded border bg-white">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-medium text-gray-800">{getStatusInfo(emailSandboxResult.status).text}</span>
                  <span className="text-xs font-bold text-gray-800">{(emailSandboxResult.riskScore * 100).toFixed(0)}%</span>
                </div>

                <p className="text-xs text-gray-700 mb-1 break-all">
                  <span className="font-semibold">From:</span> {emailSandboxResult.sender}
                </p>
                <p className="text-xs text-gray-700 mb-1 break-all">
                  <span className="font-semibold">Subject:</span> {emailSandboxResult.subject}
                </p>
                <p className="text-xs text-gray-600 mb-2 break-all">
                  <span className="font-semibold">Body:</span> {emailSandboxResult.body}
                </p>

                {renderReasons(emailSandboxResult.reasons)}
              </div>
            )}
          </>
        )}
      </div>

      {/* Quick Report */}
      <div className="p-4 border-t">
        <div className="flex items-center space-x-2 mb-2">
          <Flag className="w-4 h-4 text-amber-600" />
          <span className="text-sm font-medium text-gray-700">Report Issue</span>
        </div>

        {reportSubmitted ? (
          <div className="bg-green-50 p-2 rounded text-center">
            <Check className="w-4 h-4 text-green-600 mx-auto mb-1" />
            <p className="text-xs text-green-700">Report submitted{reportType ? ` (${reportType})` : ""}!</p>
          </div>
        ) : (
          <div className="grid grid-cols-3 gap-2">
            <button
              onClick={() => handleReport("phishing")}
              className="p-2 bg-red-50 hover:bg-red-100 rounded border border-red-200 transition-colors"
            >
              <AlertTriangle className="w-4 h-4 text-red-600 mx-auto" />
              <span className="text-xs text-red-700 mt-1 block">Phishing</span>
            </button>
            <button
              onClick={() => handleReport("false_positive")}
              className="p-2 bg-green-50 hover:bg-green-100 rounded border border-green-200 transition-colors"
            >
              <ThumbsUp className="w-4 h-4 text-green-600 mx-auto" />
              <span className="text-xs text-green-700 mt-1 block">Safe</span>
            </button>
            <button
              onClick={() => handleReport("false_negative")}
              className="p-2 bg-blue-50 hover:bg-blue-100 rounded border border-blue-200 transition-colors"
            >
              <ThumbsDown className="w-4 h-4 text-blue-600 mx-auto" />
              <span className="text-xs text-blue-700 mt-1 block">Missed</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default App;
