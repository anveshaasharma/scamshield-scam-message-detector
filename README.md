# 🛡️ ScamShield: Scam Message Detector

ScamShield is a small website that checks a suspicious **SMS or WhatsApp message** and shows **how likely it is to be a scam, and why**. It focuses on scams that are common in India (fake KYC, lottery, electricity bill, courier, job offers, UPI tricks and more).

It is built with only **HTML, CSS and vanilla JavaScript**: no frameworks, no backend, no database.

> 🔒 **Privacy:** all analysis happens locally in your browser. No message is stored or sent anywhere.

## ✨ Features

- Paste a message and click **Analyze Message** (or press `Ctrl + Enter`)
- **Risk score from 0 to 100%** with an animated meter and a Low (green) / Medium (orange) / High (red) badge
- **"Why this looks suspicious"** list that explains every red flag in simple language
- **Highlights** suspicious words and links directly inside your message
- **"What you should do"** safety advice (don't click, don't share OTP, block, report)
- **"Is this safe?"** result for messages with no red flags (with a reminder that no tool is 100% accurate)
- **"Try an example"** buttons with fake KYC, lottery, electricity bill, job and courier scams
- **Indian cybercrime reporting** info: helpline **1930**, [cybercrime.gov.in](https://cybercrime.gov.in) and Sanchar Saathi
- Dark / light mode toggle (remembered in your browser), fully responsive for mobile and desktop

## 🚀 How to run

No installation needed.

1. Download or clone this repository.
2. Double-click `index.html` to open it in any modern browser.

**Deploy on GitHub Pages:** go to the repository **Settings → Pages**, choose **Deploy from a branch**, select the `main` branch and the `/ (root)` folder, then save. Your site will be live at `https://<your-username>.github.io/<repo-name>/`.

## 📁 Project structure

| File | What it does |
| --- | --- |
| `index.html` | The page structure: header, detector, how it works, scam types, report, footer |
| `style.css` | All the styling, including dark/light themes and responsive layout |
| `script.js` | The detection rules, the scoring engine and the user interface logic |

## 🧠 How it works

1. **Rules:** `script.js` has a `RULES` array. Each rule has a `weight` (points) and one or more `patterns` (regular expressions) or a `check` function.
2. **Scan:** `analyzeMessage(text)` runs every rule on the message. A rule that matches adds its points **once**.
3. **Combo bonus:** some red flags are scarier together (for example, a bank name **plus** a suspicious link), so `COMBOS` adds a few extra points.
4. **Score:** the total is capped at 100 and shown as a percentage.
   - **0 flags** → Safe
   - **1–29%** → Low
   - **30–59%** → Medium
   - **60–100%** → High
5. **Explain:** the matched text is highlighted in the message, and each rule's plain-language `why` explanation is shown.

### What the rules check

Urgency words · requests for OTP / PIN / CVV / Aadhaar / PAN · fake KYC and bank warnings · lottery / prize / cashback claims · shortened links, lookalike domains (like `sbi-kyc-update.xyz`), risky website endings, random-looking links and HTTP links · fake jobs and registration fees · pretending to be a bank, government, courier or telecom · bill / courier / fine threats · requests to install AnyDesk, TeamViewer or APK files · requests to send money · phone numbers asking you to call or WhatsApp · too many CAPITALS or exclamation marks and poor grammar.

### Adding your own rule

Open `script.js`, find the `RULES` array and add an object like this:

```js
{
  id: "crypto",                       // unique short name
  title: "Crypto investment promise", // heading shown to the user
  icon: "🪙",
  weight: 20,                         // points added to the risk score
  why: "Nobody can guarantee profits from crypto or trading.",
  tip: "Never invest through a stranger's app or group.",
  patterns: [/\bguaranteed\s+(?:profit|returns?)\b/i, /\bdouble your (?:money|investment)\b/i]
}
```

Save the file and refresh. The new rule is used for scoring, highlighting and the "What ScamShield checks" list automatically.

## ⚠️ Limitations

- It uses **simple keyword/pattern rules**, not real intelligence. New scam wording can slip through.
- It can show **false alarms** (for example, a genuine bank message that mentions OTP or KYC).
- It does **not** open links or check whether a website is really dangerous. It only inspects the link text.
- It mainly understands **English** (and Hinglish words that are written in the rules). Messages in other languages or scripts are not analysed well.
- **No tool is 100% accurate.** Use it as a helper, and when in doubt, call your bank on its official number or dial **1930**.

## 🔮 Future improvements

- Train a **machine learning model** (for example, Naive Bayes or a small neural network) on labelled scam / not-scam messages, and combine it with the rules
- Add **Hindi and other Indian languages** (including Hinglish and Devanagari text)
- Build a **browser extension** that checks messages in WhatsApp Web or Gmail
- Check links against a **blocklist** such as Google Safe Browsing
- Add a **QR code / screenshot scanner** using on-device OCR
- Let users **share results** or export a report to submit with a complaint
- Add unit tests for the rules

## 📞 Report cyber fraud (India)

- Helpline: **1930**
- Portal: <https://cybercrime.gov.in>
- Report suspicious calls and messages: <https://sancharsaathi.gov.in>

## 📄 License

Free to use for learning and education.
