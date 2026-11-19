/* =====================================================================
   ScamShield: script.js
   ---------------------------------------------------------------------
   Everything runs in the browser. No message is stored or sent anywhere.

   HOW THIS FILE IS ORGANISED (read it top to bottom):
     PART 1  Settings        – score limits, lists of brands / link shorteners
     PART 2  RULES           – the detection rules (EDIT THIS to add new rules)
     PART 3  Engine          – finds red flags and calculates the risk score
     PART 4  Examples        – sample scam messages for the demo buttons
     PART 5  User interface  – buttons, highlighting, animations, dark mode

   THE BIG IDEA
     1. Each rule has a list of patterns (regular expressions) and a point value.
     2. If a pattern is found in the message, the rule "triggers" and adds its points.
     3. Total points (max 100) = the risk percentage.
        0–29 = Low, 30–59 = Medium, 60+ = High.
   ===================================================================== */

"use strict"; // Makes JavaScript stricter, so silly typos are caught early.

/* =====================================================================
   PART 1: SETTINGS
   ===================================================================== */

// Risk levels: the score at which a message becomes Medium or High risk.
const LEVELS = { medium: 30, high: 60 };

// Link shorteners hide the real website, which is why scammers love them.
const SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "is.gd", "rb.gy", "shorturl.at",
  "ow.ly", "tiny.cc", "s.id", "t.ly", "rebrand.ly", "v.gd", "buff.ly", "lnkd.in", "bl.ink", "shrtco.de"
];

// Website endings (TLDs) that are cheap and very often used for scam sites.
const SUSPICIOUS_TLDS = [
  "xyz", "top", "click", "live", "icu", "vip", "tk", "ml", "ga", "cf", "gq", "buzz",
  "cyou", "sbs", "cfd", "rest", "work", "site", "online", "link", "support", "help", "monster", "fun"
];

// Brand names scammers copy in fake domains (e.g. "sbi-kyc-update.xyz").
const BRAND_KEYWORDS = [
  "sbi", "hdfc", "icici", "axis", "kotak", "pnb", "paytm", "phonepe", "gpay", "googlepay", "amazon",
  "flipkart", "indiapost", "speedpost", "trai", "uidai", "aadhaar", "aadhar", "incometax", "epfo",
  "rbi", "jio", "airtel", "bsnl", "irctc", "fastag", "npci", "bijli", "electricity", "bses",
  "tatapower", "bescom", "dhl", "fedex", "bluedart", "delhivery", "yono"
];

// Extra words that make a short brand name suspicious when glued to it (e.g. "sbikyc", "updatesbi").
const SCAM_WORDS = [
  "kyc", "update", "verify", "login", "secure", "reward", "bank", "online", "card", "care",
  "support", "help", "refund", "claim", "offer", "bonus", "gift", "yono", "pay", "netbanking"
];

// The REAL websites of those brands. A link to these is NOT treated as a lookalike.
const OFFICIAL_DOMAINS = [
  "sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "hdfcbank.com", "icicibank.com", "axisbank.com",
  "kotak.com", "pnbindia.in", "paytm.com", "phonepe.com", "amazon.in", "amazon.com", "flipkart.com",
  "indiapost.gov.in", "trai.gov.in", "uidai.gov.in", "incometax.gov.in", "epfindia.gov.in", "rbi.org.in",
  "jio.com", "airtel.in", "bsnl.co.in", "irctc.co.in", "npci.org.in", "dhl.com", "fedex.com",
  "bluedart.com", "delhivery.com", "tatapower.com", "bsesdelhi.com", "google.com"
];

/* =====================================================================
   PART 2: THE RULES  (this is the part to edit when you want to add more!)
   ---------------------------------------------------------------------
   Each rule is an object with these fields:

     id        – a short unique name (no spaces)
     title     – the heading shown to the user
     icon      – an emoji shown next to the heading
     weight    – points added to the risk score if the rule triggers (bigger = scarier)
     why       – a simple explanation shown to the user
     tip       – (optional) a rule-specific safety tip shown in "What you should do"
     patterns  – a list of regular expressions (regex). If ANY matches, the rule triggers.
                 Always add the "i" flag so UPPER/lower case doesn't matter.
     check     – (optional) a function for things regex can't do (like analysing links).
                 It receives the text and returns a list of {start, end, text} matches.
     skipIfNegated – (optional) true = ignore matches like "do NOT share your OTP"
                 (genuine banks say this, scammers don't).

   Each rule only counts ONCE, no matter how many times it matches.

   TO ADD A NEW RULE: copy any rule below, change the fields, and save. That's all!
   ===================================================================== */

// Words for sensitive details. Used by the "sensitive information" rule below.
const SENSITIVE_ITEMS =
  "otp|one[- ]time[- ]password|upi[- ]?pin|atm[- ]?pin|pin|cvv|cvc|aadhaar|aadhar|pan(?:[- ]card)?|" +
  "card[- ]number|debit[- ]card|credit[- ]card|password|net[- ]?banking|expiry[- ]date|account[- ]number";

const RULES = [
  /* ---------- 1. Urgency & pressure ---------- */
  {
    id: "urgency",
    title: "Urgency or pressure",
    icon: "⏰",
    weight: 15,
    why: "Scammers rush you so you don't have time to think or ask someone. Real banks and companies don't threaten you with tight deadlines.",
    tip: "Stop and breathe. A real emergency never has to be solved in the next 10 minutes over a message.",
    patterns: [
      /\b(immediately|urgent(?:ly)?|asap|right now|act now|hurry(?: up)?|last chance|final (?:notice|warning|reminder|call)|today only|expires? (?:today|tonight|soon)|limited time)\b/i,
      /\bwithin\s+(?:the\s+next\s+)?\d+\s*(?:hours?|hrs?|minutes?|mins?|days?)\b/i,
      /\b(?:will|shall) be\s+(?:blocked|suspended|closed|deactivated|disconnected|frozen|terminated|cancelled|canceled)\b/i,
      /\b(?:tonight|by midnight|by today|today itself)\b/i
    ]
  },

  /* ---------- 2. Asking for sensitive information ---------- */
  {
    id: "sensitive",
    title: "Asks for OTP, PIN or private details",
    icon: "🔑",
    weight: 35,
    why: "Nobody genuine (not your bank, not the police, not a company) will ever ask for your OTP, PIN, CVV, password, Aadhaar or PAN over a message. Whoever has your OTP can take your money.",
    tip: "If you already shared an OTP, PIN or card details, call your bank right now to block the card or account, then call 1930.",
    skipIfNegated: true, // "Do not share your OTP" is a warning, not a request
    patterns: [
      // 1) an asking-word followed (within ~40 characters) by a sensitive item, e.g. "share your OTP"
      new RegExp("\\b(?:share|send|give|tell|provide|enter|submit|confirm|verify|reply(?: with)?|forward|type|fill)\\b[^.!?\\n]{0,40}?\\b(?:" + SENSITIVE_ITEMS + ")\\b", "i"),
      // 2) the item followed by "required / needed", e.g. "OTP is required"
      new RegExp("\\b(?:" + SENSITIVE_ITEMS + ")\\b\\s*(?:is\\s+|are\\s+)?(?:required|needed|mandatory)", "i"),
      // 3) "...with your Aadhaar and bank account number"
      new RegExp("\\b(?:with|using)\\s+your\\s+(?:" + SENSITIVE_ITEMS + ")\\b", "i")
    ]
  },

  /* ---------- 3. Fake KYC / bank account scams ---------- */
  {
    id: "kyc",
    title: "Fake KYC / bank account warning",
    icon: "🏦",
    weight: 25,
    why: "“KYC expired” or “account suspended” messages are one of the most common frauds in India. The link takes you to a fake bank page that steals your login and OTP.",
    tip: "Banks never fix KYC through a link in an SMS or WhatsApp. Visit the bank branch or use the official app that you installed yourself.",
    patterns: [
      /\bkyc\b[^.!?\n]{0,30}?\b(?:expired?|expiring|pending|update[ds]?|verification|verify|incomplete|not updated|suspended|invalid)\b/i,
      /\b(?:update|complete|verify|renew|upgrade)\b[^.!?\n]{0,15}\bkyc\b/i,
      /\b(?:account|a\/c|card|net ?banking|upi|wallet|sim)\b[^.!?\n]{0,20}\b(?:has been |is |will be |been )?(?:suspended|blocked|frozen|deactivated|restricted|locked)\b/i,
      /\bpan\b[^.!?\n]{0,20}\b(?:not linked|invalid|blocked|suspended)\b/i,
      /\blink\s+(?:your\s+)?(?:pan|aadhaar|aadhar)\b/i
    ]
  },

  /* ---------- 4. Lottery / prize / reward claims ---------- */
  {
    id: "lottery",
    title: "Prize, lottery or reward claim",
    icon: "🎁",
    weight: 25,
    why: "You can't win a lottery you never entered. “Prizes” and “cashback” are bait: you'll be asked to pay a fee or share bank details to receive them.",
    tip: "Ignore it. If something sounds too good to be true, it is. Never pay money to receive a prize.",
    patterns: [
      /\byou\s*(?:['’]ve|\s+have)?\s+(?:just\s+)?won\b/i,
      /\byou\s+are\s+(?:the\s+)?(?:lucky\s+)?winner\b/i,
      /\byou(?:['’]ve|\s+have)\s+been\s+selected\b/i,
      /\b(?:lucky\s+draw|lottery|jackpot|kbc|bumper\s+prize|congratulations?|prize|cash\s?back|reward\s+points?|free\s+gift|gift\s+(?:card|voucher|hamper)|\bgift\b)/i,
      /\b(?:redeem|claim)\b[^.!?\n]{0,20}\b(?:reward|points|gift|prize|cash\s?back|amount)\b/i
    ]
  },

  /* ---------- 5. Fake job / work-from-home offers ---------- */
  {
    id: "job",
    title: "Too-good-to-be-true job offer",
    icon: "💼",
    weight: 25,
    why: "Genuine employers don't offer thousands per day for easy tasks, and they never charge a registration or security fee. These offers are used to steal your money or involve you in fraud.",
    tip: "Never pay money to get a job. Check the company on its official website and never join unknown Telegram or WhatsApp “task” groups.",
    patterns: [
      /\bwork\s*from\s*home\b|\bwfh\b/i,
      /\b(?:earn|income|salary)\b[^.!?\n]{0,25}?(?:rs\.?|₹|inr)?\s*\d[\d,]*\s*(?:\/-)?[^.!?\n]{0,15}\b(?:daily|per day|a day|everyday|per week|weekly|per month|monthly)\b/i,
      /\b(?:easy|quick|fast|guaranteed)\s+(?:money|income|earning|earnings|cash)\b/i,
      /\b(?:part[- ]?time|online)\s+(?:job|work|earning)\b/i,
      /\bregistration\s+(?:fee|charge|amount)\b|\bsecurity\s+deposit\b|\brefundable\s+deposit\b/i,
      /\bno\s+(?:experience|investment|qualification)\b/i,
      /\b(?:like|subscribe|rate)\b[^.!?\n]{0,25}\b(?:youtube|videos?|reels?|instagram|products?)\b/i,
      /\bjoin\b[^.!?\n]{0,25}\b(?:telegram|whatsapp)\s+(?:group|channel)\b/i,
      /\bdata\s+entry\b|\bimmediate\s+joining\b/i
    ]
  },

  /* ---------- 6. Pretending to be a bank, government, courier, telecom ---------- */
  {
    id: "impersonation",
    title: "Pretends to be a trusted organisation",
    icon: "🎭",
    weight: 12,
    why: "Scammers copy the names of banks, government bodies, courier and telecom companies because you already trust them. Anyone can type “SBI” or “TRAI” in an SMS.",
    tip: "Don't trust the name in the message. Contact the organisation yourself using the phone number on its official website or the back of your card.",
    patterns: [
      /\b(?:sbi|state bank(?: of india)?|hdfc(?: bank)?|icici(?: bank)?|axis bank|kotak|pnb|punjab national bank|bank of baroda|canara bank|union bank|idfc|yes bank|indusind|paytm|phone ?pe|google ?pay|gpay|bhim|amazon|flipkart|myntra|india ?post|speed ?post|blue ?dart|dtdc|dhl|fedex|delhivery|ecom express|trai|uidai|aadhaar|aadhar|income ?tax(?: department)?|epfo|rbi|reserve bank|electricity board|bijli|bses|tata power|adani electricity|msedcl|bescom|jio|airtel|vodafone|bsnl|customs|police|cbi|narcotics|sebi|irctc|fastag)\b/i
    ]
  },

  /* ---------- 7. Bills, courier and fine threats ---------- */
  {
    id: "threat",
    title: "Fake bill, courier or fine notice",
    icon: "📦",
    weight: 20,
    why: "“Electricity will be cut tonight”, “parcel on hold”, “pay a small delivery fee” or “pending challan” are common tricks to make you click a link or call a fake “officer”.",
    tip: "Check your bill or parcel yourself in the official app or website (typed by you). Electricity boards and couriers don't ask for payment through random links or calls.",
    patterns: [
      /\b(?:electricity|power|light|bijli)\b[^.!?\n]{0,40}\b(?:disconnect(?:ed|ion)?|cut|bill|unpaid|pending|overdue)\b/i,
      /\bbill\b[^.!?\n]{0,25}\b(?:pending|unpaid|overdue|not (?:been )?paid|not updated)\b/i,
      /\b(?:package|parcel|consignment|shipment|courier|delivery)\b[^.!?\n]{0,40}\b(?:held|on hold|stuck|returned|failed|undelivered|pending|incomplete|seized|detained)\b/i,
      /\b(?:address|pincode|pin code)\b[^.!?\n]{0,20}\b(?:incomplete|incorrect|invalid|wrong|not found)\b/i,
      /\b(?:customs|clearance|redelivery|re-delivery)\s+(?:duty|fee|charges?)\b/i,
      /\b(?:e-?challan|traffic (?:fine|challan)|pending fine)\b/i
    ]
  },

  /* ---------- 8. Asking you to install an app ---------- */
  {
    id: "app",
    title: "Asks you to install an app or APK",
    icon: "📲",
    weight: 25,
    why: "Apps like AnyDesk or TeamViewer let a stranger see and control your phone, including your banking apps and OTPs. APK files from links can hide malware.",
    tip: "Never install apps from links or at a stranger's request. If you already did, uninstall it, turn off internet and call your bank and 1930.",
    patterns: [
      /\b(?:any\s?desk|team\s?viewer|quick\s?support|rust\s?desk|ammyy|ultra\s?viewer|air\s?droid|screen\s?shar(?:e|ing)|remote\s+(?:access|support|control))\b/i,
      /[\w.-]+\.apk\b|\bapk\b/i,
      /\b(?:install|download)\b[^.!?\n]{0,20}\b(?:app|application|software|file)\b/i
    ]
  },

  /* ---------- 9. Asking you to send money ---------- */
  {
    id: "money",
    title: "Asks you to pay or send money",
    icon: "💸",
    weight: 20,
    why: "Being asked to pay a “small fee” or “deposit” to get a prize, parcel, loan or job is a classic trap. You never need to pay to receive money.",
    tip: "Do not pay, and never approve a UPI “collect request” or scan a QR code to receive money. Your UPI PIN is only for sending money.",
    patterns: [
      /\b(?:send|transfer|pay|deposit|remit)\b[^.!?\n]{0,25}?(?:rs\.?|₹|inr)\s*\d[\d,]*/i,
      /\b(?:send|transfer|pay|deposit)\b[^.!?\n]{0,15}?\d[\d,]*\s*(?:rs\b|rupees|\/-)/i,
      /\b(?:processing|service|handling|delivery|clearance|redelivery|release)\s+(?:fee|charges?)\b/i,
      /\bpay\s+(?:a\s+)?(?:small\s+)?(?:fee|amount|charge|tax)\b/i,
      /\bscan\s+(?:the\s+|this\s+)?qr\b/i,
      /\bapprove\b[^.!?\n]{0,15}\b(?:collect|payment|request)\b/i
    ]
  },

  /* ---------- 10. Suspicious links (all use the 'check' function) ---------- */
  {
    id: "link-shortener",
    title: "Shortened link (hides the real website)",
    icon: "🔗",
    weight: 20,
    why: "Links like bit.ly or tinyurl hide where you'll really land. Banks and genuine companies rarely use them for important account messages.",
    tip: "Do not tap the link. If you need to check something, open the official app or type the website address yourself.",
    check: (text) => findLinks(text).filter((l) => SHORTENERS.includes(l.host))
  },
  {
    id: "link-lookalike",
    title: "Fake, lookalike website name",
    icon: "🕸️",
    weight: 25,
    why: "The link uses a famous name (like “sbi”) inside a website that is NOT the real one, for example sbi-kyc-update.xyz. These fake pages copy the real site to steal your details.",
    tip: "Real bank websites have short, simple addresses (like sbi.co.in). Never log in through a link you received in a message.",
    check: (text) => findLinks(text).filter((l) => isLookalikeDomain(l.host))
  },
  {
    id: "link-tld",
    title: "Link ends in a risky website ending",
    icon: "⚠️",
    weight: 15,
    why: "Endings like .xyz, .top, .click or .live are very cheap, so scammers use them a lot. Genuine banks and government sites use .com, .in, .co.in or .gov.in.",
    check: (text) => findLinks(text).filter((l) => SUSPICIOUS_TLDS.includes(l.tld))
  },
  {
    id: "link-random",
    title: "Link looks random or odd",
    icon: "🎲",
    weight: 15,
    why: "The website name has a jumble of letters, numbers or hyphens (or is just an IP address). Real organisations use clean, readable names.",
    check: (text) => findLinks(text).filter((l) => looksRandom(l.host))
  },
  {
    id: "link-http",
    title: "Link is not secure (HTTP, not HTTPS)",
    icon: "🔓",
    weight: 10,
    why: "A link that starts with http:// (without the “s”) is not encrypted. Real banks always use https://.",
    check: (text) => findLinks(text).filter((l) => l.scheme === "http")
  },

  /* ---------- 11. Pressure to click ---------- */
  {
    id: "click",
    title: "Pushes you to click or tap",
    icon: "👆",
    weight: 10,
    why: "Scam messages want you to act straight away by tapping a link. Think twice before tapping anything you didn't expect.",
    patterns: [
      /\b(?:click|tap|open|visit|follow)\b[^.!?\n]{0,15}\b(?:here|link|below|url|website)\b/i,
      /\b(?:login|log in|pay|update|verify|claim|track)\s+(?:now|here|below)\b/i
    ]
  },

  /* ---------- 12. Phone numbers asking you to call / WhatsApp ---------- */
  {
    id: "phone",
    title: "Asks you to call or WhatsApp a number",
    icon: "☎️",
    weight: 10,
    why: "Scammers want you on a call or chat where they can pressure you in real time. “Customer care” numbers inside random messages are often fake.",
    tip: "Never call numbers from a message. Find the official number on the company's website or on your card.",
    patterns: [
      /\b(?:call|contact|whatsapp|dial|reach|ring|text|message|msg)\b[^.!?\n]{0,30}?(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b/i,
      /\b(?:call|contact)\b[^.!?\n]{0,30}?\b1800[\s-]?\d{3}[\s-]?\d{3,4}\b/i,
      /\b(?:wa\.me\/\d+|api\.whatsapp\.com\/send\S*|t\.me\/\S+)/i
    ]
  },

  /* ---------- 13. Writing style: grammar, CAPITALS, exclamation marks ---------- */
  {
    id: "grammar",
    title: "Generic greeting or poor grammar",
    icon: "✍️",
    weight: 8,
    why: "Scam messages are often written carelessly or start with “Dear customer” because they are sent to thousands of people. Your real bank uses your name.",
    patterns: [
      /\bdear\s+(?:customer|user|sir|madam|sir\/madam|valued customer|account\s*holder|bank customer|client|member|winner)\b/i,
      /\bkindly\b/i,
      /\bdo the needful\b|\brevert back\b/i,
      /\b(?:plz|pls|u r)\b/i,
      /\b(?:have|has)\s+been\s+(?:block|suspend|expire|lock|deactivate)\b/i,
      / [,.!?]/ // a space BEFORE punctuation, like "account ." (a sloppy-writing sign)
    ]
  },
  {
    id: "caps",
    title: "Too many CAPITAL LETTERS",
    icon: "🔠",
    weight: 8,
    why: "Shouting in capital letters is used to create panic and grab your attention.",
    // We only trigger when a big share of the letters are capitals.
    check: (text) => {
      const letters = text.match(/[A-Za-z]/g) || [];
      const upper = text.match(/[A-Z]/g) || [];
      if (letters.length < 20 || upper.length / letters.length < 0.4) return [];
      return regexMatches(text, /\b[A-Z]{3,}\b/g); // highlight the SHOUTED words
    }
  },
  {
    id: "exclaim",
    title: "Too many exclamation marks!!!",
    icon: "❗",
    weight: 6,
    why: "Real banks and companies write calmly. Lots of exclamation marks are a way to create excitement or fear.",
    check: (text) => {
      const marks = regexMatches(text, /!+/g);
      const total = marks.reduce((sum, m) => sum + m.text.length, 0);
      return total >= 3 ? marks : [];
    }
  }
];

/* ---------------------------------------------------------------------
   COMBO BONUSES: some red flags are scarier TOGETHER.
   A combo adds extra points when ALL the rule ids in `needs` triggered,
   and (if `needsAny` is given) at least ONE of those also triggered.
   --------------------------------------------------------------------- */
const LINK_RULE_IDS = ["link-shortener", "link-lookalike", "link-tld", "link-random", "link-http"];

const COMBOS = [
  {
    id: "combo-name-link",
    title: "A trusted name AND a suspicious link together",
    icon: "🎣",
    bonus: 10,
    needs: ["impersonation"],
    needsAny: LINK_RULE_IDS,
    why: "Pretending to be a bank or government body and pushing a suspicious link is the classic phishing recipe."
  },
  {
    id: "combo-secret-urgent",
    title: "Asking for secrets while rushing you",
    icon: "🚨",
    bonus: 10,
    needs: ["sensitive", "urgency"],
    why: "Asking for private codes AND setting a deadline is exactly how scammers stop you from thinking."
  }
];

/* =====================================================================
   PART 3: THE ENGINE (no HTML in here. It just analyses text)
   ===================================================================== */

/* ---------- Small helper: get all matches of a regex ----------
   Returns a list of {start, end, text}. We add the "g" (global) flag so
   we can find EVERY match, not just the first one. */
function regexMatches(text, pattern) {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  const re = new RegExp(pattern.source, flags);
  const found = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m[0].length === 0) { re.lastIndex++; continue; } // avoid infinite loops
    found.push({ start: m.index, end: m.index + m[0].length, text: m[0] });
  }
  return found;
}

/* ---------- Is the match negated, like "do NOT share your OTP"? ---------- */
function isNegated(text, start) {
  const before = text.slice(Math.max(0, start - 30), start).toLowerCase();
  return /\b(?:do not|don't|dont|never|should not|shouldn't|will not|won't|not to)\b/.test(before);
}

/* ---------- Find all links in the message ----------
   Returns objects like:
   { start, end, text, scheme: "http" | "https" | "", host: "sbi-kyc-update.xyz", tld: "xyz" } */
const LINK_REGEX = new RegExp(
  "(?:https?:\\/\\/|www\\.)[^\\s<>\"')]+" +                      // anything starting with http://, https:// or www.
  "|\\b[a-z0-9][a-z0-9-]*(?:\\.[a-z0-9][a-z0-9-]*)*\\.(?:com|in|co\\.in|net|org|xyz|top|click|live|info|" +
  "site|online|icu|vip|cc|tk|ml|ga|cf|gq|buzz|link|shop|store|app|me|ly|gl|co|us|biz|work|support|help|" +
  "rest|cyou|sbs|cfd|fun|monster|id|is|ee)(?:\\/[^\\s<>\"')]*)?(?=$|[\\s.,;:!?)\"'<>])", // or a bare "name.com/path"
  "gi"
);

function findLinks(text) {
  const links = [];
  for (const m of regexMatches(text, LINK_REGEX)) {
    // Remove sentence punctuation stuck to the end of a link, e.g. "http://x.xyz."
    let raw = m.text.replace(/[.,;:!?)]+$/, "");
    const scheme = /^https:\/\//i.test(raw) ? "https" : /^http:\/\//i.test(raw) ? "http" : "";
    // Host = the website name only (no http://, no path, no port, no "www.")
    const host = raw.replace(/^https?:\/\//i, "").split(/[\/?#:]/)[0].toLowerCase().replace(/^www\./, "");
    if (!host.includes(".")) continue;
    // Ignore things that look like file names or email domains inside an email address
    if (m.start > 0 && text[m.start - 1] === "@") continue;
    links.push({
      start: m.start,
      end: m.start + raw.length,
      text: raw,
      scheme,
      host,
      tld: host.split(".").pop()
    });
  }
  return links;
}

/* ---------- Is this website the REAL one of that brand? ---------- */
function isOfficialDomain(host) {
  if (host.endsWith(".gov.in") || host.endsWith(".nic.in")) return true; // Indian government sites
  return OFFICIAL_DOMAINS.some((d) => host === d || host.endsWith("." + d));
}

/* ---------- Does the website name copy a brand but isn't the real site? ---------- */
function isLookalikeDomain(host) {
  if (isOfficialDomain(host)) return false;
  // Break "sbi-kyc-update.xyz" into pieces: ["sbi", "kyc", "update", "xyz"]
  const tokens = host.split(/[.-]/);
  return BRAND_KEYWORDS.some((brand) => {
    if (brand.length >= 5) return host.includes(brand);          // long names: simple "contains" check
    return tokens.some((t) =>                                    // short names (sbi, jio…): avoid false matches
      t === brand || SCAM_WORDS.some((w) => t === brand + w || t === w + brand)
    );
  });
}

/* ---------- Does the website name look random / machine-made? ---------- */
function looksRandom(host) {
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return true; // an IP address like 192.168.1.5
  const labels = host.split(".").slice(0, -1);              // everything except the ending (.com)
  return labels.some((label) => {
    const digits = (label.match(/\d/g) || []).length;
    const letters = (label.match(/[a-z]/g) || []).length;
    const hyphens = (label.match(/-/g) || []).length;
    return (
      (digits >= 3 && letters >= 3 && label.length >= 7) ||     // mix of letters and numbers, like "x7k9q2m1"
      /[bcdfghjklmnpqrstvwxyz]{6,}/.test(label) ||               // long run of consonants = not a real word
      hyphens >= 3                                               // lots of hyphens
    );
  });
}

/* ---------- Run ONE rule on the text; returns its matches ---------- */
function findMatches(text, rule) {
  let matches = [];
  if (rule.patterns) {
    for (const p of rule.patterns) matches = matches.concat(regexMatches(text, p));
  }
  if (rule.check) matches = matches.concat(rule.check(text));
  if (rule.skipIfNegated) matches = matches.filter((m) => !isNegated(text, m.start));
  return matches;
}

/* ---------- THE MAIN FUNCTION: analyse a message ----------
   Returns:
   {
     score:   0–100,
     level:   "safe" | "low" | "medium" | "high",
     flags:   [ {id, title, icon, weight, why, tip, severity, matches:[…]} ],
     ranges:  [ {start, end, titles, severity} ]  <- used to highlight the text
   } */
function analyzeMessage(text) {
  const flags = [];
  const triggered = new Set(); // ids of rules that triggered (used for combos)
  let total = 0;

  // 1) Check every rule
  for (const rule of RULES) {
    const matches = findMatches(text, rule);
    if (matches.length === 0) continue;
    triggered.add(rule.id);
    total += rule.weight;
    flags.push({
      id: rule.id, title: rule.title, icon: rule.icon, weight: rule.weight,
      why: rule.why, tip: rule.tip, matches,
      severity: rule.weight >= 20 ? "high" : "med" // decides the highlight colour
    });
  }

  // 2) Add combo bonuses (only if there is already something suspicious)
  for (const combo of COMBOS) {
    const hasAll = combo.needs.every((id) => triggered.has(id));
    const hasAny = !combo.needsAny || combo.needsAny.some((id) => triggered.has(id));
    if (hasAll && hasAny) {
      total += combo.bonus;
      flags.push({
        id: combo.id, title: combo.title, icon: combo.icon, weight: combo.bonus,
        why: combo.why, tip: null, matches: [], severity: "high", isCombo: true
      });
    }
  }

  // 3) Biggest red flags first
  flags.sort((a, b) => b.weight - a.weight);

  // 4) Turn total points into a 0–100 score and a level
  const score = Math.min(100, total);
  let level = "safe";
  if (flags.length > 0) level = score >= LEVELS.high ? "high" : score >= LEVELS.medium ? "medium" : "low";

  return { score, level, flags, ranges: buildRanges(flags) };
}

/* ---------- Work out which parts of the text to highlight ----------
   Overlapping matches are merged into one highlight so the HTML stays valid. */
function buildRanges(flags) {
  const all = [];
  for (const f of flags) {
    for (const m of f.matches) all.push({ start: m.start, end: m.end, titles: [f.title], severity: f.severity });
  }
  all.sort((a, b) => a.start - b.start || b.end - a.end);

  const merged = [];
  for (const r of all) {
    const last = merged[merged.length - 1];
    if (last && r.start < last.end) {                 // overlaps the previous one → merge
      last.end = Math.max(last.end, r.end);
      if (!last.titles.includes(r.titles[0])) last.titles.push(r.titles[0]);
      if (r.severity === "high") last.severity = "high";
    } else {
      merged.push({ ...r, titles: [...r.titles] });
    }
  }
  return merged;
}

/* =====================================================================
   PART 4: EXAMPLE SCAM MESSAGES (all fake, for demo purposes)
   ===================================================================== */
const EXAMPLES = [
  {
    label: "🏦 Fake KYC",
    text: "Dear SBI customer, your KYC has expired and your account will be blocked within 24 hours. Update immediately at http://sbi-kyc-update.xyz and enter your OTP to confirm. Do not ignore!"
  },
  {
    label: "🎁 Lottery",
    text: "CONGRATULATIONS!!! You have won Rs 25,00,000 in the KBC Lucky Draw! Claim your prize now. Pay a small processing fee of Rs 5000 and WhatsApp us on 9876543210 with your Aadhaar and bank account number."
  },
  {
    label: "💡 Electricity bill",
    text: "Dear consumer, your electricity bill of last month is unpaid. Your power will be disconnected tonight at 9:30 PM. Call our officer immediately on 9876543210 and install the QuickSupport app to update details."
  },
  {
    label: "💼 Job offer",
    text: "Work from home! Earn Rs 5000 daily just by liking YouTube videos. No experience needed. Pay a registration fee of Rs 500 (refundable). Join our Telegram group now: https://bit.ly/3xEarnNow"
  },
  {
    label: "📦 Courier",
    text: "India Post: Your parcel is on hold because the address is incomplete. Pay a redelivery fee of Rs 25 within 12 hours or it will be returned: http://indiapost-redelivery.top/track"
  },
  {
    label: "✅ Normal message",
    text: "Hi Rahul, are we still meeting at the library at 6 pm today? Bring the notes for the cyber security assignment. See you there!"
  }
];

/* =====================================================================
   PART 5: USER INTERFACE
   Code below talks to the web page (the DOM). It only runs in a browser.
   ===================================================================== */

/* Safely turn text into HTML: stops "<script>" in a message from running.
   This is important: the message is untrusted text. */
function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/* Build the highlighted version of the message as HTML. */
function renderHighlightedMessage(text, ranges) {
  let html = "";
  let cursor = 0;
  for (const r of ranges) {
    html += escapeHtml(text.slice(cursor, r.start));                 // normal text before the highlight
    const cls = r.severity === "high" ? "mark-high" : "mark-med";
    const tooltip = escapeHtml("Why: " + r.titles.join(" + "));
    html += `<mark class="${cls}" title="${tooltip}">${escapeHtml(text.slice(r.start, r.end))}</mark>`;
    cursor = r.end;
  }
  html += escapeHtml(text.slice(cursor));                            // the rest of the text
  return html;
}

/* General safety advice, always shown. */
const GENERAL_ADVICE = [
  "Do not click any link in the message, and don't reply to it.",
  "Never share your OTP, UPI PIN, CVV, card number or passwords with anyone, even if they say they are from your bank.",
  "Block the sender and delete the message (or report it as spam in your messaging app).",
  "Show the message to a family member or friend you trust before you act on anything.",
  "Report it: call 1930 or visit cybercrime.gov.in, and forward spam SMS to 1909."
];

if (typeof document !== "undefined") {
  // Tell the CSS that JavaScript is working (turns on scroll animations).
  document.documentElement.classList.add("js");

  // Grab the page elements we need, by their id from index.html.
  const $ = (id) => document.getElementById(id);
  const input = $("messageInput");
  const analyzeBtn = $("analyzeBtn");
  const clearBtn = $("clearBtn");
  const errorBox = $("inputError");
  const charCount = $("charCount");
  const resultsBox = $("results");
  const METER_LENGTH = 326.73; // circumference of the ring (2 × π × 52), must match style.css

  /* ---------- Show the result on screen ---------- */
  function showResult(text) {
    const result = analyzeMessage(text);

    // Colour theme of the whole result block: level-safe / low / medium / high
    resultsBox.className = "results level-" + result.level;
    resultsBox.hidden = false;

    // Badge + headline + summary
    const texts = {
      safe:   { badge: "No red flags", head: "Looks safe: no red flags found", sum: "We didn't find any common scam patterns. Stay careful anyway: no tool is perfect." },
      low:    { badge: "Low risk", head: "Low risk, but stay careful", sum: "A few small warning signs were found. It's probably not dangerous, but don't share personal details." },
      medium: { badge: "Medium risk", head: "Be careful: this looks suspicious", sum: "This message has several scam-like features. Don't click links or reply until you've verified it independently." },
      high:   { badge: "High risk", head: "Very likely a scam!", sum: "This message matches many known scam tricks. Do not click, reply, pay or share anything." }
    };
    $("riskBadge").textContent = texts[result.level].badge;
    $("riskHeadline").textContent = texts[result.level].head;
    $("riskSummary").textContent = texts[result.level].sum;

    animateMeter(result.score);

    const safe = result.level === "safe";
    $("safeCard").hidden = !safe;
    $("detailsGrid").hidden = safe;
    $("adviceCard").hidden = safe;

    if (!safe) {
      // Highlighted message
      $("highlightedMessage").innerHTML = renderHighlightedMessage(text, result.ranges);

      // "Why this looks suspicious" list
      const list = $("flagList");
      list.innerHTML = "";
      result.flags.forEach((f, i) => {
        const li = document.createElement("li");
        li.className = "flag-item sev-" + f.severity;
        li.style.animationDelay = i * 70 + "ms"; // items appear one after another
        // Show up to 3 different pieces of text that triggered this flag
        const found = [...new Set(f.matches.map((m) => m.text.trim()))].slice(0, 3);
        const foundHtml = found.length
          ? `<div class="flag-found"><span class="muted">Found:</span>${found
              .map((t) => `<span class="found-chip">${escapeHtml(t.length > 60 ? t.slice(0, 57) + "…" : t)}</span>`)
              .join("")}</div>`
          : "";
        li.innerHTML =
          `<span class="flag-icon" aria-hidden="true">${f.icon}</span>` +
          `<div><div class="flag-head"><span class="flag-title">${escapeHtml(f.title)}</span>` +
          `<span class="flag-points">+${f.weight} points</span></div>` +
          `<p class="flag-why">${escapeHtml(f.why)}</p>${foundHtml}</div>`;
        list.appendChild(li);
      });

      // "What you should do": tips specific to what was found first, then general advice
      const tips = [...new Set(result.flags.map((f) => f.tip).filter(Boolean))].slice(0, 4);
      const advice = $("adviceList");
      advice.innerHTML = "";
      [...tips, ...GENERAL_ADVICE].forEach((t) => {
        const li = document.createElement("li");
        li.textContent = t;
        advice.appendChild(li);
      });
    }

    // Scroll so the user sees the result
    resultsBox.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  /* ---------- Animate the ring, the bar and the number counting up ---------- */
  function animateMeter(score) {
    const fill = $("meterFill");
    const bar = $("barFill");
    // Reset to empty first so the animation replays on every analysis
    fill.style.transition = "none"; bar.style.transition = "none";
    fill.style.strokeDashoffset = METER_LENGTH; bar.style.width = "0%";
    void fill.getBoundingClientRect(); // forces the browser to apply the reset
    fill.style.transition = ""; bar.style.transition = "";
    fill.style.strokeDashoffset = METER_LENGTH * (1 - score / 100);
    bar.style.width = score + "%";
    $("riskBar").setAttribute("aria-valuenow", score);

    // Count the number from 0 up to the score
    const label = $("riskPercent");
    const duration = 1000;
    const start = performance.now();
    function tick(now) {
      const t = Math.min(1, (now - start) / duration);
      label.textContent = Math.round(score * (1 - Math.pow(1 - t, 3))); // ease-out
      if (t < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  /* ---------- Button: Analyze ---------- */
  function onAnalyze() {
    const text = input.value;
    if (text.trim() === "") {
      errorBox.textContent = "Please paste a message first.";
      input.focus();
      return;
    }
    errorBox.textContent = "";
    showResult(text);
  }
  analyzeBtn.addEventListener("click", onAnalyze);
  input.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") onAnalyze(); // Ctrl+Enter shortcut
  });

  /* ---------- Button: Clear ---------- */
  clearBtn.addEventListener("click", () => {
    input.value = "";
    errorBox.textContent = "";
    resultsBox.hidden = true;
    updateCount();
    input.focus();
  });

  /* ---------- Character counter ---------- */
  function updateCount() {
    charCount.textContent = input.value.length + " / " + input.maxLength + " characters";
  }
  input.addEventListener("input", () => { updateCount(); errorBox.textContent = ""; });

  /* ---------- Example buttons (built from the EXAMPLES array) ---------- */
  const exampleBox = $("exampleButtons");
  EXAMPLES.forEach((ex) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "chip";
    btn.textContent = ex.label;
    btn.addEventListener("click", () => {
      input.value = ex.text;
      updateCount();
      errorBox.textContent = "";
      resultsBox.hidden = true; // hide the old result until they press Analyze
      input.scrollIntoView({ behavior: "smooth", block: "center" });
      input.focus({ preventScroll: true });
    });
    exampleBox.appendChild(btn);
  });

  /* ---------- "What ScamShield checks": list generated from RULES ---------- */
  const rulesList = $("rulesList");
  RULES.forEach((rule) => {
    const li = document.createElement("li");
    li.innerHTML = `<span aria-hidden="true">${rule.icon}</span> ${escapeHtml(rule.title)} <span class="pts">+${rule.weight}</span>`;
    rulesList.appendChild(li);
  });

  /* ---------- Dark / light mode ----------
     We store the choice in localStorage so it's remembered next time.
     (try/catch because some browsers block storage in private mode.) */
  const root = document.documentElement;
  const themeBtn = $("themeToggle");

  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    themeBtn.querySelector(".theme-icon").textContent = theme === "dark" ? "☀️" : "🌙";
    themeBtn.setAttribute("aria-label", theme === "dark" ? "Switch to light mode" : "Switch to dark mode");
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", theme === "dark" ? "#060d1f" : "#eef3ff");
  }

  let savedTheme = null;
  try { savedTheme = localStorage.getItem("scamshield-theme"); } catch (e) { /* storage unavailable */ }
  applyTheme(savedTheme === "light" ? "light" : "dark"); // dark is the default "cyber" look

  themeBtn.addEventListener("click", () => {
    const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    applyTheme(next);
    try { localStorage.setItem("scamshield-theme", next); } catch (e) { /* ignore */ }
  });

  /* ---------- Mobile menu ---------- */
  const menuBtn = $("menuToggle");
  const nav = $("mainNav");
  menuBtn.addEventListener("click", () => {
    const open = nav.classList.toggle("open");
    menuBtn.setAttribute("aria-expanded", String(open));
  });
  nav.querySelectorAll("a").forEach((a) =>
    a.addEventListener("click", () => { nav.classList.remove("open"); menuBtn.setAttribute("aria-expanded", "false"); })
  );

  /* ---------- Scroll-reveal animation ---------- */
  const revealEls = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) { entry.target.classList.add("visible"); observer.unobserve(entry.target); }
      });
    }, { threshold: 0.12 });
    revealEls.forEach((el) => observer.observe(el));
  } else {
    revealEls.forEach((el) => el.classList.add("visible")); // old browsers: just show everything
  }

  updateCount();
}
