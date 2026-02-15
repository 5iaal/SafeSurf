import React, { useState, useEffect } from "react";
import axios from "axios";
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  X,
  Wifi,
  Mail,
  Search,
  Loader,
  Flag,
  ThumbsUp,
  ThumbsDown,
  Check,
  Settings,
  Trash2,
} from "lucide-react";

const App = () => {
  const [detectionMode, setDetectionMode] = useState("url"); // 'url' or 'email'
  const [currentUrl, setCurrentUrl] = useState("login.paypal-secure.verify.com");
  const [emailSender, setEmailSender] = useState("support@paypal-security.verify.com");
  const [emailSubject, setEmailSubject] = useState("Urgent: Verify Your Account");
  const [emailBodyPreview, setEmailBodyPreview] = useState(
    "Click here to verify your account immediately or it will be suspended..."
  );

  const [riskScore, setRiskScore] = useState(0);
  const [detectionStatus, setDetectionStatus] = useState("safe");
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Sandbox states
  const [sandboxInput, setSandboxInput] = useState("");
  const [sandboxResult, setSandboxResult] = useState(null);
  const [isSandboxAnalyzing, setIsSandboxAnalyzing] = useState(false);

  // Report states
  const [reportSubmitted, setReportSubmitted] = useState(false);
  const [reportType, setReportType] = useState(null);

  // تحليل النصوص الواقعي بالbackend
  const analyzeInput = async (text, type) => {
    try {
      setIsAnalyzing(true);
      const payload =
        type === "url"
          ? { type: "url", value: text }
          : {
              type: "email",
              value: { sender: emailSender, subject: emailSubject, body: emailBodyPreview },
            };

      const response = await axios.post("http://127.0.0.1:8000/analyze", payload);
      setRiskScore(response.data.riskScore);
      setDetectionStatus(response.data.status);
    } catch (err) {
      console.error("Error analyzing input:", err);
      setRiskScore(0);
      setDetectionStatus("safe");
    } finally {
      setIsAnalyzing(false);
    }
  };

  useEffect(() => {
    // تحليل تلقائي عند تغيير URL أو email
    if (detectionMode === "url") analyzeInput(currentUrl, "url");
    else analyzeInput(null, "email");
  }, [currentUrl, emailSender, emailSubject, emailBodyPreview, detectionMode]);

  const getStatusInfo = () => {
    switch (detectionStatus) {
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

  const analyzeSandboxInput = async () => {
    if (!sandboxInput.trim()) return;
    setIsSandboxAnalyzing(true);
    setSandboxResult(null);

    try {
      const payload =
        detectionMode === "url"
          ? { type: "url", value: sandboxInput }
          : {
              type: "email",
              value: { sender: emailSender, subject: emailSubject, body: sandboxInput },
            };

      const response = await axios.post("http://127.0.0.1:8000/analyze", payload);
      setSandboxResult({ input: sandboxInput, status: response.data.status, riskScore: response.data.riskScore });
    } catch (err) {
      console.error("Sandbox analysis failed:", err);
    } finally {
      setIsSandboxAnalyzing(false);
    }
  };

  const handleReport = (type) => {
    setReportType(type);
    setReportSubmitted(true);
    setTimeout(() => setReportSubmitted(false), 2000);
  };

  const StatusIcon = getStatusInfo().icon;

  return (
    <div className="w-80 min-h-[520px] bg-white shadow-lg rounded-lg overflow-hidden">
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
            onClick={() => setDetectionMode("url")}
            className={`flex-1 flex items-center justify-center space-x-1 py-1.5 px-2 text-xs font-medium rounded transition-colors ${
              detectionMode === "url" ? "bg-blue-600 text-white" : "text-gray-600 hover:text-gray-800"
            }`}
          >
            <Wifi className="w-3 h-3" />
            <span>URL</span>
          </button>
          <button
            onClick={() => setDetectionMode("email")}
            className={`flex-1 flex items-center justify-center space-x-1 py-1.5 px-2 text-xs font-medium rounded transition-colors ${
              detectionMode === "email" ? "bg-blue-600 text-white" : "text-gray-600 hover:text-gray-800"
            }`}
          >
            <Mail className="w-3 h-3" />
            <span>Email</span>
          </button>
        </div>
      </div>

      {/* Current Analysis */}
      <div className="p-4 border-b">
        {detectionMode === "url" ? (
          <>
            <div className="flex items-center space-x-2 mb-2">
              <Wifi className="w-4 h-4 text-gray-500" />
              <span className="text-xs text-gray-500">Current page:</span>
            </div>
            <p className="text-sm font-mono text-gray-800 bg-gray-50 p-2 rounded break-all">{currentUrl}</p>
          </>
        ) : (
          <>
            <div className="flex items-center space-x-2 mb-2">
              <Mail className="w-4 h-4 text-gray-500" />
              <span className="text-xs text-gray-500">Opened email:</span>
            </div>
            <div className="space-y-2">
              <div className="bg-gray-50 p-2 rounded">
                <p className="text-xs font-medium text-gray-700 break-all">From: {emailSender}</p>
                <p className="text-xs font-medium text-gray-800 mt-1 break-all">Subject: {emailSubject}</p>
              </div>
              <div className="bg-gray-50 p-2 rounded">
                <p className="text-xs text-gray-600 italic break-all">"{emailBodyPreview}"</p>
              </div>
            </div>
          </>
        )}
      </div>

      {/* Risk Status */}
      <div className="p-4 text-center">
        {isAnalyzing ? (
          <div className="py-4">
            <Loader className="w-5 h-5 text-blue-600 animate-spin mx-auto mb-2" />
            <p className="text-sm text-gray-600">Analyzing...</p>
          </div>
        ) : (
          <>
            <div className={`inline-flex items-center justify-center w-12 h-12 ${getStatusInfo().color} rounded-full mb-3`}>
              <StatusIcon className="w-6 h-6 text-white" />
            </div>
            <p className="font-semibold text-gray-900 mb-1">{getStatusInfo().text}</p>
            <p className="text-sm text-gray-600">Risk: {(riskScore * 100).toFixed(0)}%</p>
          </>
        )}
      </div>

      {/* Sandbox Analyzer */}
      <div className="p-4 border-t bg-gray-50">
        <div className="flex items-center space-x-2 mb-3">
          <Search className="w-4 h-4 text-gray-600" />
          <span className="text-sm font-medium">{detectionMode === "url" ? "Test URL" : "Test Email"}</span>
        </div>

        <div className="flex space-x-2 mb-3">
          <input
            type="text"
            value={sandboxInput}
            onChange={(e) => setSandboxInput(e.target.value)}
            placeholder={detectionMode === "url" ? "Enter URL to test" : "Enter email content to test"}
            className="flex-1 text-xs p-2 border border-gray-300 rounded focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
            onKeyDown={(e) => e.key === "Enter" && analyzeSandboxInput()}
          />
          <button
            onClick={analyzeSandboxInput}
            disabled={isSandboxAnalyzing || !sandboxInput.trim()}
            className="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white p-2 rounded transition-colors"
          >
            {isSandboxAnalyzing ? <Loader className="w-3 h-3 animate-spin" /> : <Search className="w-3 h-3" />}
          </button>
        </div>

        {sandboxResult && (
          <div
            className={`p-3 rounded border ${
              sandboxResult.status === "high_risk"
                ? "bg-red-50 border-red-200"
                : sandboxResult.status === "low_risk"
                ? "bg-yellow-50 border-yellow-200"
                : "bg-green-50 border-green-200"
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span
                className={`text-xs font-medium ${
                  sandboxResult.status === "high_risk"
                    ? "text-red-700"
                    : sandboxResult.status === "low_risk"
                    ? "text-yellow-700"
                    : "text-green-700"
                }`}
              >
                {sandboxResult.status === "high_risk"
                  ? "Phishing Detected"
                  : sandboxResult.status === "low_risk"
                  ? "Suspicious"
                  : "Safe"}
              </span>
              <span
                className={`text-xs font-bold ${
                  sandboxResult.status === "high_risk"
                    ? "text-red-600"
                    : sandboxResult.status === "low_risk"
                    ? "text-yellow-600"
                    : "text-green-600"
                }`}
              >
                {(sandboxResult.riskScore * 100).toFixed(0)}%
              </span>
            </div>
            <p className="text-xs text-gray-600 mb-2 truncate">{sandboxResult.input}</p>
            <div className="flex space-x-1">
              {sandboxResult.status === "high_risk" ? (
                <button className="w-full bg-red-600 text-white text-xs py-1 px-2 rounded">Mark as Spam</button>
              ) : (
                <button className="w-full bg-green-600 text-white text-xs py-1 px-2 rounded">Keep Email</button>
              )}
            </div>
          </div>
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
            <p className="text-xs text-green-700">Report submitted!</p>
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
