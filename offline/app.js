(() => {
  "use strict";

  const MODEL = window.SAFESCAN_MODEL;
  if (!MODEL || !MODEL.vectorizer || !MODEL.model) {
    // Fail loudly so it's obvious in WebView / browser console.
    throw new Error("SafeScan model data missing (model.js not loaded).");
  }

  const MAX_HISTORY = 12;
  const MAX_URLS = 10;
  const MAX_ANALYSIS_CHARS = 8000;
  const MAX_HISTORY_SNIPPET_CHARS = 180;
  const STORAGE_LANG_KEY = "safescan_lang";
  const STORAGE_HISTORY_KEY = "safescan_history";
  const RISK_CAUTION_MIN = 55;
  const RISK_UNSAFE_MIN = 70;

  const AR_LETTER_RE = /[\u0600-\u06FF]/;
  const AR_DIACRITICS_RE = /[\u0610-\u061A\u064B-\u065F\u0670\u06D6-\u06ED]/g;
  const URL_RE =
    /(https?:\/\/[^\s<>"]+|www\.[^\s<>"]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:\/[^\s<>"]*)?)/gi;
  const EMAIL_RE = /\b[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}\b/g;

  const AR_STOPWORDS = new Set([
    "في",
    "على",
    "من",
    "الى",
    "إلى",
    "عن",
    "أن",
    "إن",
    "كان",
    "ما",
    "هذا",
    "هذه",
    "ذلك",
    "تلك",
    "هناك",
    "مع",
    "او",
    "أو",
    "ثم",
    "كما",
    "لقد"
  ]);

  const EN_STOPWORDS = new Set([
    "the",
    "is",
    "in",
    "on",
    "at",
    "and",
    "or",
    "to",
    "of",
    "a",
    "an",
    "for",
    "we",
    "you",
    "your",
    "our"
  ]);

  const SUSPICIOUS_KEYWORDS_EN_STRONG = new Set([
    "verify",
    "password",
    "login",
    "bank",
    "urgent",
    "suspended",
    "locked",
    "prize",
    "free",
    "click",
    "refund",
    "otp"
  ]);

  const SUSPICIOUS_KEYWORDS_EN_WEAK = new Set(["account", "confirm", "update", "code"]);

  const SUSPICIOUS_KEYWORDS_AR_STRONG = new Set([
    "تحقق",
    "التحقق",
    "كلمه",
    "كلمة",
    "المرور",
    "بنك",
    "بنكي",
    "ايقاف",
    "إيقاف",
    "تعليق",
    "معلق",
    "جائزه",
    "جائزة",
    "ربحت",
    "اضغط",
    "انقر",
    "رمز",
    "otp"
  ]);

  const SUSPICIOUS_KEYWORDS_AR_WEAK = new Set([
    "حساب",
    "حسابك",
    "تحديث",
    "تأكيد",
    "تاكيد",
    "تسجيل",
    "الدخول",
    "اربح"
  ]);

  const SUSPICIOUS_PHRASES_EN = new Set([
    "give me your password",
    "share your password",
    "send your password",
    "verify your account now",
    "click this link now",
    "enter your otp",
    "send otp code",
    "urgent account verification",
    "account will be suspended",
    "bank account locked",
    "claim your free prize",
    "reset your password now"
  ]);

  const SUSPICIOUS_PHRASES_AR = new Set([
    "اعطني كلمة المرور",
    "اعطيني كلمة المرور",
    "ارسل كلمة المرور",
    "أرسل كلمة المرور",
    "ارسل رمز التحقق",
    "أرسل رمز التحقق",
    "شارك رمز التحقق",
    "تحقق من حسابك الآن",
    "اضغط على الرابط الآن",
    "انقر على الرابط الآن",
    "سيتم ايقاف حسابك",
    "سيتم إيقاف حسابك",
    "حسابك مهدد",
    "تحديث بياناتك البنكية",
    "ادخل رقم البطاقة",
    "أدخل رقم البطاقة"
  ]);

  const BENIGN_HINTS_EN = new Set([
    "thank",
    "thanks",
    "contact",
    "soon",
    "appointment",
    "confirmed",
    "meeting",
    "invoice",
    "order",
    "shipped",
    "report",
    "welcome"
  ]);

  const BENIGN_HINTS_AR = new Set([
    "شكرا",
    "شكراً",
    "تواصل",
    "سنتواصل",
    "قريبا",
    "قريباً",
    "موعد",
    "الاجتماع",
    "تأكيد",
    "تاكيد",
    "الحجز",
    "اهلا",
    "أهلا"
  ]);

  const APPOINTMENT_HINTS_EN = new Set([
    "appointment",
    "meeting",
    "schedule",
    "scheduled",
    "calendar",
    "agenda",
    "invite",
    "invitation",
    "team"
  ]);

  // Keep these in normalized Arabic form to match cleanText output.
  const APPOINTMENT_HINTS_AR = new Set([
    "\u0645\u0648\u0639\u062f", // موعد
    "\u0627\u062c\u062a\u0645\u0627\u0639", // اجتماع
    "\u0627\u0644\u0627\u062c\u062a\u0645\u0627\u0639", // الاجتماع
    "\u0641\u0631\u064a\u0642", // فريق
    "\u0627\u0644\u0639\u0645\u0644", // العمل
    "\u062c\u062f\u0648\u0644", // جدول
    "\u0627\u0644\u0627\u0639\u0645\u0627\u0644", // الاعمال
    "\u0645\u0646\u0635\u0647", // منصه
    "\u0646\u0642\u0627\u0634", // نقاش
    "\u0627\u0644\u0633\u0627\u0639\u0647", // الساعه
    "\u0635\u0628\u0627\u062d\u0627", // صباحا
    "\u0645\u0633\u0627\u0621" // مساء
  ]);

  const BENIGN_WEAK_ALLOWED_KEYWORDS = new Set([
    "confirm",
    "\u062a\u0627\u0643\u064a\u062f", // تاكيد
    "\u062a\u0623\u0643\u064a\u062f" // تأكيد
  ]);

  function clamp(n, lo, hi) {
    return Math.max(lo, Math.min(hi, n));
  }

  function riskClass(riskScore) {
    if (riskScore >= RISK_UNSAFE_MIN) return "unsafe";
    if (riskScore >= RISK_CAUTION_MIN) return "caution";
    return "safe";
  }

  function isProbablyArabic(text) {
    return AR_LETTER_RE.test(String(text || ""));
  }

  function normalizeArabic(text) {
    let s = String(text || "");
    s = s.replace(AR_DIACRITICS_RE, "");
    s = s.replace(/\u0640/g, ""); // tatweel
    s = s.replace(/أ|إ|آ/g, "ا");
    s = s.replace(/ى/g, "ي");
    s = s.replace(/ؤ/g, "و").replace(/ئ/g, "ي");
    s = s.replace(/ة/g, "ه");
    return s;
  }

  function splitTokenParts(value) {
    const parts = String(value || "")
      .toLowerCase()
      .split(/[^a-z0-9\u0600-\u06FF]+/g)
      .filter((p) => p && p.length > 1);
    return parts;
  }

  function urlFeatureTokens(rawUrl) {
    const input = String(rawUrl || "").trim();
    if (!input) return [];

    const normalized = /^https?:\/\//i.test(input) ? input : `http://${input}`;
    let parsed;
    try {
      parsed = new URL(normalized);
    } catch {
      return [];
    }

    const tokens = [];
    const scheme = String(parsed.protocol || "").replace(":", "").toLowerCase();
    if (scheme) tokens.push(`url_${scheme}`);

    const host = String(parsed.hostname || "").toLowerCase().replace(/\.+$/, "");
    if (host) {
      tokens.push(...splitTokenParts(host));

      const labels = host.split(".").filter(Boolean);
      if (labels.length) tokens.push(`tld_${labels[labels.length - 1]}`);
      if ((host.match(/-/g) || []).length >= 2) tokens.push("hyphen_domain");
      if ((host.match(/\./g) || []).length >= 3) tokens.push("many_subdomains");
    }

    const pathBlob = `${parsed.pathname || ""} ${parsed.search || ""} ${parsed.hash || ""}`;
    tokens.push(...splitTokenParts(pathBlob));

    const seen = new Set();
    const out = [];
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (!t || seen.has(t)) continue;
      seen.add(t);
      out.push(t);
      if (out.length >= 20) break;
    }
    return out;
  }

  function replaceUrlMatch(matchText) {
    const raw = String(matchText || "");
    const tokens = urlFeatureTokens(raw);
    if (!tokens.length) return " URLTOKEN ";
    return ` URLTOKEN ${tokens.join(" ")} `;
  }

  function replaceEmailMatch(matchText) {
    const email = String(matchText || "").trim().toLowerCase();
    const at = email.indexOf("@");
    const domain = at >= 0 ? email.slice(at + 1) : "";
    const tokens = splitTokenParts(domain);
    if (domain) {
      const labels = domain.split(".").filter(Boolean);
      if (labels.length) tokens.push(`mail_tld_${labels[labels.length - 1]}`);
    }
    if (!tokens.length) return " EMAILTOKEN ";
    return ` EMAILTOKEN ${tokens.slice(0, 10).join(" ")} `;
  }

  function cleanText(text) {
    let s = String(text || "");
    s = s.replace(EMAIL_RE, (m) => replaceEmailMatch(m));
    s = s.replace(URL_RE, (m) => replaceUrlMatch(m));

    if (isProbablyArabic(s)) s = normalizeArabic(s);
    s = s.toLowerCase();

    // Keep: latin, digits, underscores, Arabic block.
    s = s.replace(/[^a-z0-9_\u0600-\u06FF\s]/g, " ");
    s = s.replace(/\s+/g, " ").trim();
    if (!s) return "";

    const tokens = s.split(" ");
    const out = [];
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (!t || t.length <= 1) continue;
      if (EN_STOPWORDS.has(t)) continue;
      if (AR_STOPWORDS.has(t)) continue;
      out.push(t);
    }
    return out.join(" ");
  }

  const TRANSLATIONS = {
    en: {
      title: "SafeScan Offline",
      brand: "SafeScan",
      tagline: "Phishing & scam detection (offline)",
      hero_title: "Detect suspicious links and messages in seconds.",
      hero_text:
        "Paste a URL, message, or full email. SafeScan runs URL risk checks + on-device NLP analysis.",
      badge_1: "URL risk checks",
      badge_2: "On-device NLP",
      badge_3: "Explainable report",
      example_label: "Example",
      example_text: "secure-login-paypal.com",
      feature_1_title: "URL checks",
      feature_1_text: "Flags suspicious domains, subdomains, and phishing patterns.",
      feature_2_title: "Text scanning",
      feature_2_text: "Analyses message text with an embedded NLP classifier.",
      feature_3_title: "Clear results",
      feature_3_text: "Readable explanations with a simple risk signal.",
      scan_title: "Scan now",
      scan_subtitle: "Paste a URL, message, or a full email to analyse.",
      placeholder: "Enter text or URL...",
      check: "Check",
      privacy_note: "Runs locally on your device. No data is sent anywhere.",
      confidence: "Risk score",
      nlp_confidence: "NLP confidence",
      safe: "Safe",
      caution: "Suspicious",
      unsafe: "Unsafe",
      url: "URL",
      urls: "URLs",
      text: "Text",
      email: "Email",
      you: "You",
      history_title: "History",
      history_empty: "No scans yet. Your previous checks will appear here.",
      history_note: "History is stored on this device.",
      clear_history: "Clear",
      text_analysis_title: "Text analysis",
      url_checks_title: "URL checks",
      urls_none: "No URLs detected in this input.",
      ml_safe_msg: "No major risk signals were detected in the text.",
      ml_caution_msg: "Some risk signals were found. Be careful and verify before you act.",
      ml_unsafe_msg: "High risk signals found. This may be phishing or a scam.",
      install: "Install",
      toggle: "العربية",
      footer: "Educational project • Always verify before you click."
    },
    ar: {
      title: "SafeScan (غير متصل)",
      brand: "SafeScan",
      tagline: "كشف التصيّد والاحتيال (بدون إنترنت)",
      hero_title: "اكشف الروابط والرسائل المشبوهة خلال ثوانٍ.",
      hero_text:
        "الصق رابطًا أو رسالة أو بريدًا كاملًا. يجمع SafeScan بين فحص الروابط وتحليل NLP على جهازك.",
      badge_1: "فحص الروابط",
      badge_2: "تحليل NLP",
      badge_3: "تقرير واضح",
      example_label: "مثال",
      example_text: "secure-login-paypal.com",
      feature_1_title: "فحص الروابط",
      feature_1_text: "يرصد النطاقات والكلمات والأنماط الشائعة في التصيّد.",
      feature_2_title: "تحليل الرسائل",
      feature_2_text: "يحلّل النص باستخدام نموذج NLP مُضمَّن على الجهاز.",
      feature_3_title: "نتيجة واضحة",
      feature_3_text: "شرح مبسّط مع إشارة واضحة للمخاطر.",
      scan_title: "تحقق الآن",
      scan_subtitle: "الصق رابطًا أو رسالة أو بريدًا كاملًا للتحليل.",
      placeholder: "اكتب رسالة أو رابط...",
      check: "تحقق",
      privacy_note: "يعمل على جهازك فقط. لا يتم إرسال أي بيانات.",
      confidence: "مستوى المخاطر",
      nlp_confidence: "ثقة نموذج NLP",
      safe: "آمن",
      caution: "مشبوه",
      unsafe: "غير آمن",
      url: "رابط",
      urls: "الروابط",
      text: "نص",
      email: "بريد",
      you: "أنت",
      history_title: "السجل",
      history_empty: "لا يوجد سجل بعد. ستظهر نتائج التحقق السابقة هنا.",
      history_note: "يتم حفظ السجل على هذا الجهاز.",
      clear_history: "مسح",
      text_analysis_title: "تحليل النص",
      url_checks_title: "فحص الروابط",
      urls_none: "لم يتم العثور على روابط في هذا النص.",
      ml_safe_msg: "لم يتم رصد مؤشرات كبيرة على الخطر في النص.",
      ml_caution_msg: "تم رصد بعض المؤشرات. كن حذرًا وتحقق قبل اتخاذ أي إجراء.",
      ml_unsafe_msg: "تم رصد مؤشرات عالية الخطورة. قد يكون هذا تصيّدًا أو احتيالًا.",
      install: "تثبيت",
      toggle: "English",
      footer: "مشروع تعليمي • تحقّق دائمًا قبل الضغط على أي رابط."
    }
  };

  const URL_MESSAGES_AR = {
    "Invalid URL format": "صيغة الرابط غير صحيحة",
    "Suspicious URL": "الرابط مشبوه",
    "High risk URL": "رابط عالي الخطورة",
    "Suspicious keyword found in domain": "تم العثور على كلمة مشبوهة في النطاق",
    "Too many subdomains": "يوجد عدد كبير من النطاقات الفرعية",
    "URL looks safe": "يبدو الرابط آمنًا"
  };

  const DOMAIN_SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "security",
    "account",
    "password",
    "confirm",
    "signin",
    "alert",
    "support",
    "billing",
    "invoice",
    "payment",
    "bank",
    "wallet",
    "otp",
    "free",
    "premium",
    "bonus",
    "gift",
    "reward",
    "claim",
    "winner",
    "win"
  ];

  const PATH_SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "password",
    "confirm",
    "signin",
    "reset",
    "otp",
    "code",
    "bank",
    "wallet",
    "billing",
    "invoice",
    "payment",
    "gift",
    "prize",
    "reward",
    "suspend",
    "suspended",
    "unlock",
    "recover",
    "urgent",
    "alert",
    "free",
    "premium",
    "gift",
    "bonus",
    "claim",
    "winner",
    "win"
  ];

  const EXPLICIT_PHISHING_TOKENS = new Set(["phish", "phishing"]);

  const URL_SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rebrand.ly"]);
  const RISKY_TLDS = new Set([
    "xyz",
    "top",
    "icu",
    "site",
    "click",
    "live",
    "tk",
    "monster",
    "work",
    "buzz",
    "rest",
    "fit",
    "gq",
    "country"
  ]);
  const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
  const BRAND_ALLOWLIST = {
    paypal: ["paypal.com", "paypal.me"],
    google: ["google.com", "google.co.uk", "google.ae", "googleusercontent.com", "googleapis.com", "g.co"],
    microsoft: ["microsoft.com", "live.com", "outlook.com"],
    apple: ["apple.com", "icloud.com"],
    amazon: ["amazon.com", "amazon.co.uk", "amazon.ae"],
    netflix: ["netflix.com"]
  };

  const AUTH_TERMS = new Set([
    "login",
    "signin",
    "verify",
    "account",
    "password",
    "secure",
    "security",
    "update"
  ]);
  const INCENTIVE_TERMS = new Set(["free", "premium", "gift", "bonus", "prize", "reward", "winner", "win", "claim"]);

  function round2(n) {
    return Math.round(n * 100) / 100;
  }

  function nowStamp() {
    const d = new Date();
    const pad = (x) => String(x).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(
      d.getHours()
    )}:${pad(d.getMinutes())}`;
  }

  function getLang() {
    const stored = localStorage.getItem(STORAGE_LANG_KEY);
    if (stored === "ar" || stored === "en") return stored;
    return "en";
  }

  function setLang(lang) {
    localStorage.setItem(STORAGE_LANG_KEY, lang);
  }

  function ui(lang) {
    return TRANSLATIONS[lang] || TRANSLATIONS.en;
  }

  function translateUrlMessage(messageKey, lang) {
    if (lang === "ar") return URL_MESSAGES_AR[messageKey] || messageKey;
    return messageKey;
  }

  const URL_REASON_TEMPLATES = {
    en: {
      EMPTY_URL: "Empty URL input.",
      INVALID_URL: "Invalid URL format.",
      NOT_HTTPS: "Not using HTTPS (encrypted connection).",
      HAS_AT_SYMBOL: "Contains '@' in the address (can hide the real destination).",
      NON_STANDARD_PORT: "Uses a non-standard port: {value}",
      ENCODED_OBFUSCATION: "Contains heavy URL encoding (possible obfuscation).",
      IP_ADDRESS_HOST: "Uses an IP address instead of a domain name.",
      PUNYCODE_DOMAIN: "Punycode domain (possible look-alike domain).",
      TOO_MANY_SUBDOMAINS: "Too many subdomains ({value}).",
      MANY_HYPHENS: "Many hyphens in the domain ({value}).",
      LONG_URL: "Very long URL ({value} characters).",
      RISKY_TLD: "Risky top-level domain: .{value}",
      URL_SHORTENER: "URL shortener hides the destination.",
      SUSPICIOUS_KEYWORD: "Domain contains suspicious keyword: {value}",
      MULTIPLE_SUSPICIOUS_KEYWORDS: "Multiple suspicious keywords in domain ({value}).",
      SUSPICIOUS_WORD_CLUSTER: "Domain contains a dense cluster of suspicious words ({value}).",
      SUSPICIOUS_PATH_KEYWORD: "Path/query contains suspicious keyword: {value}",
      MULTIPLE_SUSPICIOUS_PATH_KEYWORDS: "Multiple suspicious keywords in path/query ({value}).",
      INCENTIVE_AUTH_COMBO: "Domain combines lure terms (free/prize) with account/login terms.",
      EXPLICIT_PHISHING_TERM: "Explicit phishing term detected in URL.",
      BRAND_IMPERSONATION: "Brand name used in domain (possible impersonation): {value}",
      BRAND_WITH_RISK_TERMS: "Brand-like domain also includes high-risk lure/login terms: {value}",
      NO_MAJOR_FLAGS: "No major red flags detected."
    },
    ar: {
      EMPTY_URL: "لم يتم إدخال رابط.",
      INVALID_URL: "صيغة الرابط غير صحيحة.",
      NOT_HTTPS: "لا يستخدم HTTPS (اتصال غير مُشفّر).",
      HAS_AT_SYMBOL: "يحتوي على الرمز @ (قد يُخفي الوجهة الحقيقية).",
      IP_ADDRESS_HOST: "يستخدم عنوان IP بدلًا من اسم نطاق.",
      PUNYCODE_DOMAIN: "نطاق Punycode (قد يكون نطاقًا مُشابِهًا).",
      TOO_MANY_SUBDOMAINS: "عدد كبير من النطاقات الفرعية ({value}).",
      MANY_HYPHENS: "يوجد عدد كبير من الشرطات في النطاق ({value}).",
      LONG_URL: "الرابط طويل جدًا ({value} حرفًا).",
      RISKY_TLD: "امتداد نطاق عالي المخاطر: .{value}",
      URL_SHORTENER: "رابط مختصر يُخفي الوجهة.",
      SUSPICIOUS_KEYWORD: "يحتوي النطاق على كلمة مشبوهة: {value}",
      MULTIPLE_SUSPICIOUS_KEYWORDS: "وجود عدة كلمات مشبوهة في النطاق ({value}).",
      SUSPICIOUS_WORD_CLUSTER: "النطاق يحتوي على تجمع كبير من الكلمات المشبوهة ({value}).",
      INCENTIVE_AUTH_COMBO: "يجمع النطاق بين كلمات إغراء (مجاني/جائزة) وكلمات حساب/تسجيل دخول.",
      BRAND_IMPERSONATION: "يحتوي النطاق على اسم علامة تجارية وقد يكون انتحالًا: {value}",
      BRAND_WITH_RISK_TERMS: "النطاق المشابه للعلامة يحتوي أيضًا على كلمات إغراء/تسجيل دخول خطرة: {value}",
      NO_MAJOR_FLAGS: "لا توجد مؤشرات كبيرة على الخطر."
    }
  };

  function urlReasonText(reason, lang) {
    const r = reason || {};
    const code = r.code || "";
    const value = r.value || "";
    const templates = URL_REASON_TEMPLATES[lang] || URL_REASON_TEMPLATES.en;
    const template = templates[code] || URL_REASON_TEMPLATES.en[code] || code;
    return String(template).replace("{value}", String(value));
  }

  function stripUrlPunctuation(value) {
    let v = String(value || "").trim();
    v = v.replace(/^[<([{\"']+/, "");
    v = v.replace(/[)\]}>.,;:!?\"']+$/, "");
    return v.trim();
  }

  function looksLikeSingleUrl(input) {
    const value = stripUrlPunctuation(input);
    if (!value) return false;
    if (/\s/.test(value)) return false;
    if (value.includes("@")) return false;
    const re = /^(?:https?:\/\/|www\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d{2,5})?(?:\/[^\s]*)?$/i;
    return re.test(value);
  }

  function extractUrls(text) {
    const input = String(text || "");
    if (!input) return [];

    const matches = [];
    const spans = [];

    const httpRe = /https?:\/\/[^\s<>"]+/gi;
    const wwwRe = /\bwww\.[^\s<>"]+/gi;
    const bareRe = /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d{2,5})?(?:\/[^\s<>"]*)?\b/gi;

    const addMatch = (start, raw, end) => {
      const candidate = stripUrlPunctuation(raw);
      if (!candidate) return;
      if (/^mailto:/i.test(candidate)) return;
      matches.push([start, candidate]);
      if (typeof end === "number") spans.push([start, end]);
    };

    let m;
    while ((m = httpRe.exec(input)) !== null) addMatch(m.index, m[0], m.index + m[0].length);
    while ((m = wwwRe.exec(input)) !== null) addMatch(m.index, m[0], m.index + m[0].length);

    while ((m = bareRe.exec(input)) !== null) {
      const start = m.index;
      const end = m.index + m[0].length;
      if (start > 0 && input[start - 1] === "@") continue;
      let inside = false;
      for (let i = 0; i < spans.length; i++) {
        if (spans[i][0] <= start && start < spans[i][1]) {
          inside = true;
          break;
        }
      }
      if (inside) continue;
      addMatch(start, m[0], end);
    }

    matches.sort((a, b) => a[0] - b[0]);
    const urls = [];
    const seen = new Set();
    for (let i = 0; i < matches.length; i++) {
      const candidate = matches[i][1];
      const lower = candidate.toLowerCase();
      if (seen.has(lower)) continue;
      seen.add(lower);
      urls.push(candidate);
      if (urls.length >= MAX_URLS) break;
    }
    return urls;
  }

  function tokenMatch(text, token) {
    const hay = String(text || "");
    const needle = String(token || "");
    if (!hay || !needle) return false;
    if (needle.length <= 3) return hay.includes(needle);
    const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp(`(^|[^a-z0-9])${escaped}($|[^a-z0-9])`, "i").test(hay);
  }

  function safeDecode(value) {
    try {
      return decodeURIComponent(String(value || ""));
    } catch {
      return String(value || "");
    }
  }

  function checkUrl(rawUrl, lang) {
    const uiLang = lang === "ar" ? "ar" : "en";
    let url = String(rawUrl || "").trim();

    if (!url) {
      return {
        safe: false,
        result_class: "unsafe",
        risk: 100,
        messageKey: "Invalid URL format",
        reasons: [urlReasonText({ code: "EMPTY_URL" }, uiLang)]
      };
    }

    let normalized = url;
    if (!/^https?:\/\//i.test(normalized)) normalized = "http://" + normalized;

    let parsed;
    try {
      parsed = new URL(normalized);
    } catch {
      return {
        safe: false,
        result_class: "unsafe",
        risk: 100,
        messageKey: "Invalid URL format",
        reasons: [urlReasonText({ code: "INVALID_URL" }, uiLang)]
      };
    }

    const domain = String(parsed.hostname || "").replace(/\.+$/, "").toLowerCase();
    if (!domain) {
      return {
        safe: false,
        result_class: "unsafe",
        risk: 100,
        messageKey: "Invalid URL format",
        reasons: [urlReasonText({ code: "INVALID_URL" }, uiLang)]
      };
    }

    const reasons = [];
    let risk = 0;

    if (parsed.protocol !== "https:") {
      risk += 14;
      reasons.push({ code: "NOT_HTTPS" });
    }

    const afterScheme = normalized.split("//")[1] || "";
    if (afterScheme.includes("@")) {
      risk += 35;
      reasons.push({ code: "HAS_AT_SYMBOL" });
    }

    const port = parsed.port ? Number(parsed.port) : null;
    if (port !== null && port !== 80 && port !== 443) {
      risk += 12;
      reasons.push({ code: "NON_STANDARD_PORT", value: String(port) });
    }

    if ((normalized.match(/%/g) || []).length >= 3) {
      risk += 12;
      reasons.push({ code: "ENCODED_OBFUSCATION" });
    }

    if (IPV4_RE.test(domain)) {
      risk += 45;
      reasons.push({ code: "IP_ADDRESS_HOST" });
    }

    if (domain.startsWith("xn--") || domain.includes(".xn--")) {
      risk += 25;
      reasons.push({ code: "PUNYCODE_DOMAIN" });
    }

    const dotCount = (domain.match(/\./g) || []).length;
    if (dotCount > 3) {
      risk += 20;
      reasons.push({ code: "TOO_MANY_SUBDOMAINS", value: String(dotCount + 1) });
    }

    const hyphenCount = (domain.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
      risk += 20;
      reasons.push({ code: "MANY_HYPHENS", value: String(hyphenCount) });
    }

    if (normalized.length >= 100) {
      risk += 15;
      reasons.push({ code: "LONG_URL", value: String(normalized.length) });
    } else if (normalized.length >= 75) {
      risk += 8;
      reasons.push({ code: "LONG_URL", value: String(normalized.length) });
    }

    const parts = domain.split(".");
    const tld = parts.length > 1 ? parts[parts.length - 1] : "";
    if (tld && RISKY_TLDS.has(tld)) {
      risk += 18;
      reasons.push({ code: "RISKY_TLD", value: tld });
    }

    if (URL_SHORTENERS.has(domain)) {
      risk += 30;
      reasons.push({ code: "URL_SHORTENER" });
    }

    const domainKeywordHits = [];
    for (let i = 0; i < DOMAIN_SUSPICIOUS_WORDS.length; i++) {
      const w = DOMAIN_SUSPICIOUS_WORDS[i];
      if (w && domain.includes(w)) {
        domainKeywordHits.push(w);
        reasons.push({ code: "SUSPICIOUS_KEYWORD", value: w });
      }
    }

    if (domainKeywordHits.length) {
      risk += Math.min(48, 12 * domainKeywordHits.length);
    }

    if (domainKeywordHits.length >= 2) {
      risk += 18;
      reasons.push({ code: "MULTIPLE_SUSPICIOUS_KEYWORDS", value: String(domainKeywordHits.length) });
    }

    if (domainKeywordHits.length >= 3) {
      risk += 15;
      reasons.push({ code: "SUSPICIOUS_WORD_CLUSTER", value: String(domainKeywordHits.length) });
    }

    const pathQuery = [
      safeDecode(parsed.pathname),
      safeDecode(parsed.search),
      safeDecode(parsed.hash)
    ]
      .join(" ")
      .toLowerCase();

    const pathKeywordHits = [];
    for (let i = 0; i < PATH_SUSPICIOUS_WORDS.length; i++) {
      const w = PATH_SUSPICIOUS_WORDS[i];
      if (tokenMatch(pathQuery, w)) {
        pathKeywordHits.push(w);
        reasons.push({ code: "SUSPICIOUS_PATH_KEYWORD", value: w });
      }
    }

    if (pathKeywordHits.length) {
      risk += Math.min(45, 15 * pathKeywordHits.length);
    }

    if (pathKeywordHits.length >= 2) {
      risk += 12;
      reasons.push({ code: "MULTIPLE_SUSPICIOUS_PATH_KEYWORDS", value: String(pathKeywordHits.length) });
    }

    const domainTokens = new Set(domain.replace(/[^a-z0-9]+/g, " ").split(" ").filter(Boolean));
    const hasAuthTerm = Array.from(AUTH_TERMS).some((t) => domainTokens.has(t));
    const hasIncentiveTerm = Array.from(INCENTIVE_TERMS).some((t) => domainTokens.has(t));
    if (hasAuthTerm && hasIncentiveTerm) {
      risk += 22;
      reasons.push({ code: "INCENTIVE_AUTH_COMBO" });
    }

    let hasExplicitPhishing = false;
    for (const token of EXPLICIT_PHISHING_TOKENS) {
      if (domain.includes(token) || pathQuery.includes(token)) {
        hasExplicitPhishing = true;
        break;
      }
    }
    if (hasExplicitPhishing) {
      risk += 60;
      reasons.push({ code: "EXPLICIT_PHISHING_TERM" });
    }

    // Brand impersonation (tiny allowlist; educational heuristic).
    for (const brand in BRAND_ALLOWLIST) {
      if (!brand || !domain.includes(brand)) continue;
      const allowed = BRAND_ALLOWLIST[brand] || [];
      let ok = false;
      for (let i = 0; i < allowed.length; i++) {
        const sfx = allowed[i];
        if (domain === sfx || domain.endsWith("." + sfx)) {
          ok = true;
          break;
        }
      }
      if (!ok) {
        risk += 35;
        reasons.push({ code: "BRAND_IMPERSONATION", value: brand });
        if (hasAuthTerm || hasIncentiveTerm) {
          risk += 18;
          reasons.push({ code: "BRAND_WITH_RISK_TERMS", value: brand });
        }
      }
    }

    risk = clamp(risk, 0, 100);
    const riskRounded = round2(risk);
    const cls = riskClass(riskRounded);

    let messageKey = "URL looks safe";
    if (riskRounded >= RISK_UNSAFE_MIN) messageKey = "High risk URL";
    else if (riskRounded >= RISK_CAUTION_MIN) messageKey = "Suspicious URL";

    if (!reasons.length && cls === "safe") reasons.push({ code: "NO_MAJOR_FLAGS" });

    return {
      safe: cls === "safe",
      result_class: cls,
      risk: riskRounded,
      messageKey,
      reasons: reasons.map((r) => urlReasonText(r, uiLang))
    };
  }

  function makeTokenRegex() {
    // Prefer Unicode-aware tokenization similar to Python's (?u)\\b\\w\\w+\\b
    try {
      // eslint-disable-next-line no-new
      return new RegExp("[\\p{L}\\p{N}_]{2,}", "gu");
    } catch {
      return /\b\w\w+\b/g;
    }
  }

  const TOKEN_RE = makeTokenRegex();

  function tokenize(text, lowercase) {
    let s = String(text || "");
    if (lowercase) s = s.toLowerCase();
    const tokens = [];
    let m;
    TOKEN_RE.lastIndex = 0;
    while ((m = TOKEN_RE.exec(s)) !== null) tokens.push(m[0]);
    return tokens;
  }

  function buildVector(text) {
    const vec = MODEL.vectorizer;
    const terms = vec.terms;
    const idf = vec.idf;
    const n = terms.length;

    const termToIndex = new Map();
    for (let i = 0; i < n; i++) termToIndex.set(terms[i], i);

    const counts = new Array(n).fill(0);

    const cleaned = cleanText(text);
    const tokens = tokenize(cleaned, false);

    const range = vec.ngram_range || [1, 1];
    const minN = range[0] || 1;
    const maxN = range[1] || 1;

    const all = [];
    if (minN <= 1) all.push(...tokens);
    for (let ngram = Math.max(2, minN); ngram <= maxN; ngram++) {
      for (let i = 0; i + ngram <= tokens.length; i++) {
        all.push(tokens.slice(i, i + ngram).join(" "));
      }
    }

    for (let i = 0; i < all.length; i++) {
      const idx = termToIndex.get(all[i]);
      if (idx === undefined) continue;
      counts[idx] += 1;
    }

    const tfidf = new Array(n).fill(0);
    for (let i = 0; i < n; i++) {
      if (counts[i] === 0) continue;
      tfidf[i] = counts[i] * idf[i];
    }

    if (vec.norm === "l2") {
      let sumSq = 0;
      for (let i = 0; i < n; i++) sumSq += tfidf[i] * tfidf[i];
      const norm = Math.sqrt(sumSq);
      if (norm > 0) {
        for (let i = 0; i < n; i++) tfidf[i] = tfidf[i] / norm;
      }
    }

    return tfidf;
  }

  function sigmoid(x) {
    // Stable-ish sigmoid for our tiny models.
    if (x >= 0) {
      const z = Math.exp(-x);
      return 1 / (1 + z);
    }
    const z = Math.exp(x);
    return z / (1 + z);
  }

  function urlNlpRisk(urlText) {
    const x = buildVector(urlText);
    const coef = MODEL.model.coef;
    const intercept = MODEL.model.intercept;
    let score = intercept;
    for (let i = 0; i < x.length; i++) score += coef[i] * x[i];
    return round2(clamp(sigmoid(score) * 100, 0, 100));
  }

  function analyzeText(text, urls, lang) {
    const x = buildVector(text);
    const coef = MODEL.model.coef;
    const intercept = MODEL.model.intercept;

    let score = intercept;
    for (let i = 0; i < x.length; i++) score += coef[i] * x[i];

    const probaUnsafe = sigmoid(score);
    const nlpConfidence = round2(Math.max(probaUnsafe, 1 - probaUnsafe) * 100);

    let riskScore = probaUnsafe * 100;

    const cleaned = cleanText(text);
    const tokenArr = cleaned ? cleaned.split(" ") : [];
    const tokens = new Set(tokenArr);

    const strongKeywords = new Set();
    const weakKeywords = new Set();

    for (const kw of SUSPICIOUS_KEYWORDS_EN_STRONG) {
      if (tokens.has(String(kw).toLowerCase())) strongKeywords.add(kw);
    }
    for (const kw of SUSPICIOUS_KEYWORDS_AR_STRONG) {
      if (tokens.has(String(kw).toLowerCase())) strongKeywords.add(kw);
    }

    for (const kw of SUSPICIOUS_KEYWORDS_EN_WEAK) {
      if (tokens.has(String(kw).toLowerCase())) weakKeywords.add(kw);
    }
    for (const kw of SUSPICIOUS_KEYWORDS_AR_WEAK) {
      if (tokens.has(String(kw).toLowerCase())) weakKeywords.add(kw);
    }

    const foundKeywords = new Set([...Array.from(strongKeywords), ...Array.from(weakKeywords)]);

    const benignSet = isProbablyArabic(text) ? BENIGN_HINTS_AR : BENIGN_HINTS_EN;
    let benignHits = 0;
    for (const kw of benignSet) {
      if (tokens.has(String(kw).toLowerCase())) benignHits += 1;
    }

    const appointmentSet = isProbablyArabic(text) ? APPOINTMENT_HINTS_AR : APPOINTMENT_HINTS_EN;
    let appointmentHits = 0;
    for (const kw of appointmentSet) {
      if (tokens.has(String(kw).toLowerCase())) appointmentHits += 1;
    }

    const strings = ui(lang);
    const reasons = [];
    const detected = isProbablyArabic(text) ? "ar" : "en";

    if (lang === "ar") {
      reasons.push(`اللغة المكتشفة: ${detected === "ar" ? "العربية" : "الإنجليزية"}`);
      reasons.push(`احتمال الخطر (NLP): ${round2(probaUnsafe * 100)}%`);
    } else {
      reasons.push(`Detected language: ${detected === "ar" ? "Arabic" : "English"}`);
      reasons.push(`NLP risk probability: ${round2(probaUnsafe * 100)}%`);
    }

    if (urls && urls.length) {
      reasons.push(lang === "ar" ? `تم العثور على ${urls.length} رابط/روابط في النص.` : `Found ${urls.length} URL(s) in the text.`);
    }

    const phraseSet = detected === "ar" ? SUSPICIOUS_PHRASES_AR : SUSPICIOUS_PHRASES_EN;
    const haystack = `${String(text || "").toLowerCase()} ${cleaned}`;
    const phraseHits = [];
    for (const phrase of phraseSet) {
      if (haystack.includes(String(phrase).toLowerCase())) phraseHits.push(phrase);
    }
    if (phraseHits.length) {
      const shown = Array.from(new Set(phraseHits)).slice(0, 6).join(", ");
      reasons.push(
        lang === "ar" ? `عبارات خطرة مكتشفة: ${shown}` : `Detected high-risk phrases: ${shown}`
      );
      riskScore += Math.min(40, 14 + 7 * phraseHits.length);
    }

    if (foundKeywords.size) {
      const keywords = Array.from(foundKeywords).sort().join(", ");
      reasons.push(lang === "ar" ? `كلمات/عبارات مشبوهة: ${keywords}` : `Suspicious keywords: ${keywords}`);

      let boost = 0;
      boost += 12 * strongKeywords.size;
      if (weakKeywords.size >= 2) boost += 6 * weakKeywords.size;
      else if (weakKeywords.size === 1 && strongKeywords.size) boost += 4;
      riskScore += Math.min(35, boost);
    }

    const weakKeywordsOnlyBenign =
      weakKeywords.size > 0 &&
      Array.from(weakKeywords).every((kw) => BENIGN_WEAK_ALLOWED_KEYWORDS.has(String(kw).toLowerCase()));
    const hasOnlyWeakOrNone =
      strongKeywords.size === 0 && (!foundKeywords.size || weakKeywordsOnlyBenign) && phraseHits.length === 0;

    if (appointmentHits >= 2 && (!urls || !urls.length) && hasOnlyWeakOrNone) {
      reasons.push(
        lang === "ar"
          ? "يبدو النص متعلقًا بموعد/اجتماع عمل ولا يحتوي على روابط."
          : "Text appears to be a meeting/appointment message without links."
      );
      riskScore -= 46;
    } else if (benignHits >= 2 && (!urls || !urls.length) && hasOnlyWeakOrNone) {
      reasons.push(
        lang === "ar"
          ? "يبدو النص عاديًا (شكر/تأكيد/تواصل) ولا يحتوي على روابط."
          : "Text looks benign (thanks/confirmation/contact) and contains no links."
      );
      riskScore -= 22;
    }

    if (tokenArr.length <= 3 && (!urls || !urls.length) && hasOnlyWeakOrNone) {
      riskScore -= 10;
    }

    riskScore = clamp(riskScore, 0, 100);
    const resultClass = riskClass(riskScore);

    // Explainability: show the top positive-contribution terms for caution/unsafe.
    if (resultClass === "caution" || resultClass === "unsafe") {
      try {
        const names = MODEL.vectorizer.terms;
        const contribs = [];
        for (let i = 0; i < x.length; i++) {
          if (!x[i]) continue;
          const c = x[i] * coef[i];
          if (c > 0) contribs.push([names[i], c]);
        }
        contribs.sort((a, b) => b[1] - a[1]);
        const top = contribs.slice(0, 5).map((t) => t[0]);
        if (top.length) {
          reasons.push(lang === "ar" ? `أبرز إشارات NLP: ${top.join(", ")}` : `Top NLP risk terms: ${top.join(", ")}`);
        }
      } catch {}
    }

    let message = strings.ml_safe_msg;
    let icon = "✅";
    if (resultClass === "unsafe") {
      message = strings.ml_unsafe_msg;
      icon = "⚠️";
    } else if (resultClass === "caution") {
      message = strings.ml_caution_msg || strings.ml_unsafe_msg;
      icon = "⚠️";
    }

    return {
      result_class: resultClass,
      label: strings[resultClass] || resultClass,
      confidence: nlpConfidence,
      risk_score: round2(riskScore),
      icon,
      message,
      reasons
    };
  }

  function summaryMessage(lang, textResultClass, urlsTotal, urlsUnsafe, urlsCaution) {
    const strings = ui(lang);
    const textPart =
      textResultClass === "safe" || textResultClass === "caution" || textResultClass === "unsafe"
        ? `${strings.text}: ${strings[textResultClass]}`
        : "";

    let urlsPart = strings.urls_none;
    if (urlsTotal) {
      const cautionCount = Number(urlsCaution || 0);
      if (lang === "ar") {
        const extra = cautionCount ? ` • ${strings.caution}: ${cautionCount}` : "";
        urlsPart = `${strings.urls}: ${urlsTotal} (${strings.unsafe}: ${urlsUnsafe}${extra})`;
      } else {
        const extra = cautionCount ? `, ${cautionCount} suspicious` : "";
        urlsPart = `${strings.urls}: ${urlsTotal} checked (${urlsUnsafe} unsafe${extra})`;
      }
    }

    if (textPart) return `${textPart} • ${urlsPart}`;
    return urlsPart;
  }

  function analyzeInput(raw, lang) {
    const input = String(raw || "").slice(0, MAX_ANALYSIS_CHARS).trim();
    const urls = extractUrls(input);
    const isUrlOnly = looksLikeSingleUrl(input) && !/\s/.test(input);
    const strings = ui(lang);

    if (isUrlOnly) {
      const candidate = stripUrlPunctuation(input);
      const rep = checkUrl(candidate, lang);
      const mlRisk = urlNlpRisk(candidate);
      const blendedRisk =
        mlRisk >= RISK_CAUTION_MIN
          ? Math.max(Number(rep.risk || 0), Number(rep.risk || 0) * 0.65 + mlRisk * 0.35)
          : Math.max(Number(rep.risk || 0), mlRisk * 0.4);
      const confidence = round2(clamp(blendedRisk, 0, 100));
      const resultClass = riskClass(confidence);
      let messageKey = rep.messageKey;
      if (resultClass === "unsafe") messageKey = "High risk URL";
      else if (resultClass === "caution") messageKey = "Suspicious URL";
      else if (!messageKey) messageKey = "URL looks safe";
      const message = translateUrlMessage(messageKey, lang);
      const reasons = Array.isArray(rep.reasons) ? [...rep.reasons] : [];
      reasons.push(
        lang === "ar"
          ? `احتمال الخطورة عبر نموذج URL/NLP: ${mlRisk}%`
          : `URL NLP phishing probability: ${mlRisk}%`
      );

      return {
        kind: "url",
        input,
        result_class: resultClass,
        icon: resultClass === "safe" ? "✅" : "⚠️",
        label: strings[resultClass],
        confidence,
        message,
        text_details: null,
        url_details: [
          {
            url: candidate,
            result_class: resultClass,
            icon: resultClass === "safe" ? "✅" : "⚠️",
            label: strings[resultClass],
            confidence,
            message,
            reasons
          }
        ]
      };
    }

    const textDetails = analyzeText(input, urls, lang);
    const urlDetails = [];
    let urlsUnsafe = 0;
    let urlsCaution = 0;
    const urlRisks = [];
    for (let i = 0; i < urls.length; i++) {
      const candidate = urls[i];
      const rep = checkUrl(candidate, lang);
      const mlRisk = urlNlpRisk(candidate);
      const blendedRisk =
        mlRisk >= RISK_CAUTION_MIN
          ? Math.max(Number(rep.risk || 0), Number(rep.risk || 0) * 0.65 + mlRisk * 0.35)
          : Math.max(Number(rep.risk || 0), mlRisk * 0.4);
      const confidence = round2(clamp(blendedRisk, 0, 100));
      const resultClass = riskClass(confidence);
      urlRisks.push(Number(confidence || 0));
      if (resultClass === "unsafe") urlsUnsafe += 1;
      else if (resultClass === "caution") urlsCaution += 1;

      let messageKey = rep.messageKey;
      if (resultClass === "unsafe") messageKey = "High risk URL";
      else if (resultClass === "caution") messageKey = "Suspicious URL";
      else if (!messageKey) messageKey = "URL looks safe";

      const reasons = Array.isArray(rep.reasons) ? [...rep.reasons] : [];
      reasons.push(
        lang === "ar"
          ? `احتمال الخطورة عبر نموذج URL/NLP: ${mlRisk}%`
          : `URL NLP phishing probability: ${mlRisk}%`
      );

      urlDetails.push({
        url: candidate,
        result_class: resultClass,
        icon: resultClass === "safe" ? "✅" : "⚠️",
        label: strings[resultClass],
        confidence,
        message: translateUrlMessage(messageKey, lang),
        reasons
      });
    }

    const urlsTotal = urlDetails.length;

    const textRisk = Number(textDetails.risk_score || 0);
    const overallRisk = urlRisks.length ? Math.max(textRisk, Math.max(...urlRisks)) : textRisk;
    const overallClass = riskClass(overallRisk);

    const message =
      urlsTotal > 0
        ? summaryMessage(lang, textDetails.result_class, urlsTotal, urlsUnsafe, urlsCaution)
        : textDetails.message;

    const kind = input.includes("\n") || urlsTotal > 0 ? "email" : "text";

    return {
      kind,
      input,
      result_class: overallClass,
      icon: overallClass === "safe" ? "✅" : "⚠️",
      label: strings[overallClass],
      confidence: round2(overallRisk),
      message,
      text_details: textDetails,
      url_details: urlDetails
    };
  }

  function loadHistory() {
    try {
      const raw = localStorage.getItem(STORAGE_HISTORY_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  function saveHistory(items) {
    try {
      localStorage.setItem(STORAGE_HISTORY_KEY, JSON.stringify(items.slice(-MAX_HISTORY)));
    } catch {
      // ignore quota errors
    }
  }

  function addToHistory(entry) {
    const items = loadHistory();
    items.push(entry);
    saveHistory(items);
  }

  function clearHistory() {
    localStorage.removeItem(STORAGE_HISTORY_KEY);
  }

  function el(id) {
    return document.getElementById(id);
  }

  function setText(id, value) {
    const node = el(id);
    if (node) node.textContent = value;
  }

  function setHidden(id, hidden) {
    const node = el(id);
    if (node) node.hidden = !!hidden;
  }

  function renderStrings(lang) {
    const strings = ui(lang);
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
    document.title = strings.title;

    setText("brandName", strings.brand);
    setText("brandTag", strings.tagline);
    setText("heroTitle", strings.hero_title);
    setText("heroText", strings.hero_text);
    setText("badge1", strings.badge_1);
    setText("badge2", strings.badge_2);
    setText("badge3", strings.badge_3);
    setText("exampleLabel", strings.example_label + ":");
    setText("exampleText", strings.example_text);
    setText("feature1Title", strings.feature_1_title);
    setText("feature1Text", strings.feature_1_text);
    setText("feature2Title", strings.feature_2_title);
    setText("feature2Text", strings.feature_2_text);
    setText("feature3Title", strings.feature_3_title);
    setText("feature3Text", strings.feature_3_text);
    setText("scanTitle", strings.scan_title);
    setText("scanSubtitle", strings.scan_subtitle);
    setText("checkBtn", strings.check);
    setText("privacyNote", strings.privacy_note);
    setText("confidenceLabel", strings.confidence);
    setText("textAnalysisTitle", strings.text_analysis_title);
    setText("urlChecksTitle", strings.url_checks_title);
    setText("historyTitle", strings.history_title);
    setText("historyNote", strings.history_note);
    setText("historyEmpty", strings.history_empty);
    setText("clearHistoryBtn", strings.clear_history);
    setText("toggleLang", strings.toggle);
    setText("footerText", strings.footer);

    const input = el("inputText");
    if (input) input.placeholder = strings.placeholder;

    const installBtn = el("installApp");
    if (installBtn) installBtn.textContent = strings.install;
  }

  function renderHistory(lang) {
    const strings = ui(lang);
    const container = el("historyChat");
    if (!container) return;

    const items = loadHistory();
    container.innerHTML = "";

    setHidden("historyEmpty", items.length !== 0);

    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      const kindLabel =
        it.kind === "url" ? strings.url : it.kind === "email" ? strings.email : strings.text;

      const user = document.createElement("div");
      user.className = "chat-block user";
      user.innerHTML = `
        <div class="chat-meta">
          <span class="chat-who">${strings.you}</span>
          <span class="chat-kind">${kindLabel}</span>
          <span class="chat-when">${it.at || ""}</span>
        </div>
        <div class="bubble bubble-user"></div>
      `;
      user.querySelector(".bubble").textContent = it.input || "";
      container.appendChild(user);

      const bot = document.createElement("div");
      bot.className = "chat-block bot";
      const confText = it.confidence === null || it.confidence === undefined ? "" : `${it.confidence}%`;
      bot.innerHTML = `
        <div class="bubble bubble-bot ${it.result_class}">
          <div class="bubble-title">
            <span class="bubble-icon" aria-hidden="true">${it.result_class === "safe" ? "✅" : "⚠️"}</span>
            <span class="bubble-label">${
              it.result_class === "safe"
                ? strings.safe
                : it.result_class === "caution"
                  ? strings.caution
                  : strings.unsafe
            }</span>
            <span class="bubble-conf">${confText}</span>
          </div>
          <div class="bubble-text"></div>
        </div>
      `;
      bot.querySelector(".bubble-text").textContent = it.message || "";
      container.appendChild(bot);
    }

    container.scrollTop = container.scrollHeight;
  }

  function renderUrls(lang, urlDetails) {
    const strings = ui(lang);
    const urlList = el("urlList");
    const urlCount = el("urlCount");
    const urlsNone = el("urlsNone");

    if (!urlList || !urlCount || !urlsNone) return;
    urlList.innerHTML = "";

    if (!urlDetails || urlDetails.length === 0) {
      urlCount.hidden = true;
      urlsNone.hidden = false;
      urlsNone.textContent = strings.urls_none;
      return;
    }

    urlCount.hidden = false;
    urlCount.textContent = String(urlDetails.length);
    urlsNone.hidden = true;

    for (let i = 0; i < urlDetails.length; i++) {
      const u = urlDetails[i];
      const item = document.createElement("div");
      item.className = `url-item ${u.result_class}`;
      item.innerHTML = `
        <div class="url-item-top">
          <span class="url-item-icon" aria-hidden="true">${u.icon}</span>
          <span class="url-item-label">${u.label}</span>
          <span class="url-item-conf">${u.confidence}%</span>
        </div>
        <div class="url-item-value"></div>
        <div class="url-item-msg"></div>
      `;
      item.querySelector(".url-item-value").textContent = u.url;
      item.querySelector(".url-item-msg").textContent = u.message;

      if (u.reasons && u.reasons.length) {
        const ul = document.createElement("ul");
        ul.className = "reason-list reason-list--compact";
        for (let j = 0; j < u.reasons.length; j++) {
          const li = document.createElement("li");
          li.textContent = u.reasons[j];
          ul.appendChild(li);
        }
        item.appendChild(ul);
      }
      urlList.appendChild(item);
    }
  }

  function renderResult(lang, analysis) {
    const strings = ui(lang);

    setHidden("resultWrap", !analysis);
    if (!analysis) return;

    const resultBox = el("resultBox");
    if (!resultBox) return;

    resultBox.classList.remove("safe", "caution", "unsafe");
    resultBox.classList.add(analysis.result_class);

    setText("resultIcon", analysis.icon);
    setText("resultLabel", analysis.label);
    setText("resultMessage", analysis.message || "");

    const conf = analysis.confidence;
    const meter = el("overallMeter");
    const confValue = el("confidenceValue");
    const fill = el("overallFill");

    if (conf === null || conf === undefined) {
      if (meter) meter.hidden = true;
    } else {
      if (meter) meter.hidden = false;
      if (confValue) confValue.textContent = `${conf}%`;
      if (fill) fill.style.width = `${Math.max(0, Math.min(100, conf))}%`;
    }

    const textCard = el("textCard");
    const textMiniMeter = el("textMiniMeter");
    const textPill = el("textPill");
    const textReasons = el("textReasonList");

    if (analysis.text_details) {
      if (textCard) textCard.hidden = false;
      setText("textPillIcon", analysis.text_details.icon);
      setText("textPillLabel", analysis.text_details.label);
      setText("textDetailMessage", analysis.text_details.message);

      if (textPill) {
        textPill.classList.remove("safe", "caution", "unsafe");
        textPill.classList.add(analysis.text_details.result_class);
      }

      if (textMiniMeter) {
        textMiniMeter.classList.remove("safe", "caution", "unsafe");
        textMiniMeter.classList.add(analysis.text_details.result_class);
      }

      const tconf = analysis.text_details.confidence;
      setText("textMiniLabel", strings.nlp_confidence || strings.confidence);
      setText("textMiniValue", `${tconf}%`);
      const tfill = el("textMiniFill");
      if (tfill) tfill.style.width = `${Math.max(0, Math.min(100, tconf))}%`;

      if (textReasons) {
        if (analysis.text_details.reasons && analysis.text_details.reasons.length) {
          textReasons.hidden = false;
          textReasons.innerHTML = "";
          for (let i = 0; i < analysis.text_details.reasons.length; i++) {
            const li = document.createElement("li");
            li.textContent = analysis.text_details.reasons[i];
            textReasons.appendChild(li);
          }
        } else {
          textReasons.hidden = true;
          textReasons.innerHTML = "";
        }
      }
    } else {
      if (textCard) textCard.hidden = true;
      if (textReasons) {
        textReasons.hidden = true;
        textReasons.innerHTML = "";
      }
    }

    renderUrls(lang, analysis.url_details || []);
  }

  function initServiceWorker() {
    if (!("serviceWorker" in navigator)) return;
    // Service workers only work on HTTPS (or localhost). Android WebView file:// won't use it.
    if (location.protocol !== "https:" && location.hostname !== "localhost" && location.hostname !== "127.0.0.1")
      return;

    // Avoid reloading on first install; reload only when an update takes over.
    let hadController = !!navigator.serviceWorker.controller;
    window.addEventListener("load", () => {
      navigator.serviceWorker
        .register("./sw.js")
        .then((reg) => {
          try {
            reg.update();
          } catch (e) {}
        })
        .catch(() => {});
    });

    navigator.serviceWorker.addEventListener("controllerchange", () => {
      if (!hadController) {
        hadController = true;
        return;
      }
      if (window.__swReloading) return;
      window.__swReloading = true;
      window.location.reload();
    });
  }

  function initInstallButton(lang) {
    const installBtn = el("installApp");
    if (!installBtn) return;

    let deferredPrompt = null;

    window.addEventListener("beforeinstallprompt", (e) => {
      e.preventDefault();
      deferredPrompt = e;
      installBtn.hidden = false;
    });

    window.addEventListener("appinstalled", () => {
      deferredPrompt = null;
      installBtn.hidden = true;
    });

    installBtn.addEventListener("click", () => {
      if (!deferredPrompt) return;
      installBtn.disabled = true;
      deferredPrompt.prompt();
      deferredPrompt.userChoice
        .then(() => {
          deferredPrompt = null;
          installBtn.hidden = true;
        })
        .catch(() => {
          deferredPrompt = null;
        })
        .then(() => {
          installBtn.disabled = false;
        });
    });

    installBtn.textContent = ui(lang).install;
  }

  function init() {
    let lang = getLang();
    renderStrings(lang);
    renderHistory(lang);
    initServiceWorker();
    initInstallButton(lang);

    const toggle = el("toggleLang");
    if (toggle) {
      toggle.addEventListener("click", (e) => {
        e.preventDefault();
        lang = lang === "ar" ? "en" : "ar";
        setLang(lang);
        renderStrings(lang);
        renderHistory(lang);
      });
    }

    const clearBtn = el("clearHistoryBtn");
    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        clearHistory();
        renderHistory(lang);
      });
    }

    const form = el("scanForm");
    const input = el("inputText");
    if (form && input) {
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        const raw = String(input.value || "").trim();
        if (!raw) return;

        const analysis = analyzeInput(raw, lang);
        renderResult(lang, analysis);

        const snippet = raw.slice(0, MAX_HISTORY_SNIPPET_CHARS);
        addToHistory({
          at: nowStamp(),
          kind: analysis.kind,
          input: snippet,
          result_class: analysis.result_class,
          confidence: analysis.confidence,
          message: analysis.message
        });
        renderHistory(lang);
      });
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
