import type { ThreatIndicator } from "./schema.js";
import { randomUUID } from "crypto";

// Array of realistic mock threat indicators for offline mode
export const OFFLINE_DATASET: Omit<ThreatIndicator, "id">[] = [
  // --- Botnet Nodes ---
  {
    type: "IP",
    value: "192.168.1.100", // Example IP
    reputation: "malicious",
    confidence_score: 98,
    country: "RU",
    sources: JSON.stringify(["Offline-Botnet-Feed"]),
    tags: JSON.stringify(["mirai", "botnet", "scanner"]),
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    raw_data: JSON.stringify({ note: "Known Mirai botnet node" }),
  },
  {
    type: "IP",
    value: "103.45.67.89",
    reputation: "malicious",
    confidence_score: 95,
    country: "CN",
    sources: JSON.stringify(["Offline-Botnet-Feed"]),
    tags: JSON.stringify(["botnet", "ssh-bruteforce"]),
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    raw_data: JSON.stringify({ note: "SSH brute-force bot" }),
  },
  {
    type: "IP",
    value: "45.12.34.56",
    reputation: "malicious",
    confidence_score: 90,
    country: "BR",
    sources: JSON.stringify(["Offline-Botnet-Feed"]),
    tags: JSON.stringify(["ddos", "botnet", "qakbot"]),
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    raw_data: JSON.stringify({ note: "Qakbot participant" }),
  },
  // --- TOR Exit Nodes ---
  {
    type: "IP",
    value: "185.220.101.5",
    reputation: "suspicious",
    confidence_score: 75,
    country: "DE",
    sources: JSON.stringify(["Offline-Tor-Nodes"]),
    tags: JSON.stringify(["tor", "anonymizer"]),
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    raw_data: JSON.stringify({ note: "Known TOR Exit Node" }),
  },
  {
    type: "IP",
    value: "109.70.100.11",
    reputation: "suspicious",
    confidence_score: 75,
    country: "AT",
    sources: JSON.stringify(["Offline-Tor-Nodes"]),
    tags: JSON.stringify(["tor", "anonymizer"]),
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    raw_data: JSON.stringify({ note: "Known TOR Exit Node" }),
  },
  {
    type: "IP",
    value: "193.23.244.244",
    reputation: "suspicious",
    confidence_score: 70,
    country: "NL",
    sources: JSON.stringify(["Offline-Tor-Nodes"]),
    tags: JSON.stringify(["tor", "anonymizer"]),
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    raw_data: JSON.stringify({ note: "Known TOR Exit Node" }),
  },
  // --- Phishing Infrastructure ---
  {
    type: "IP",
    value: "172.67.12.34",
    reputation: "malicious",
    confidence_score: 85,
    country: "US",
    sources: JSON.stringify(["Offline-Phish-Feed"]),
    tags: JSON.stringify(["phishing", "credential-harvesting"]),
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    raw_data: JSON.stringify({ note: "Hosting Microsoft 365 phishing pages" }),
  },
  {
    type: "IP",
    value: "198.51.100.22",
    reputation: "malicious",
    confidence_score: 88,
    country: "US",
    sources: JSON.stringify(["Offline-Phish-Feed"]),
    tags: JSON.stringify(["phishing", "paypal-scam"]),
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    raw_data: JSON.stringify({ note: "PayPal phishing site" }),
  },
  // --- Command and Control (C2) ---
  {
    type: "IP",
    value: "91.214.124.124",
    reputation: "malicious",
    confidence_score: 100,
    country: "RU",
    sources: JSON.stringify(["Offline-C2-Tracker"]),
    tags: JSON.stringify(["c2", "cobalt-strike", "apt29"]),
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    raw_data: JSON.stringify({ note: "Cobalt Strike Team Server" }),
  },
  {
    type: "IP",
    value: "8.2.3.4",
    reputation: "malicious",
    confidence_score: 96,
    country: "RO",
    sources: JSON.stringify(["Offline-C2-Tracker"]),
    tags: JSON.stringify(["c2", "empire", "backdoor"]),
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    raw_data: JSON.stringify({ note: "PowerShell Empire C2" }),
  },
  // --- Additional IPs (Generating up to 50 for realistic feel) ---
];

// Dynamically generate the remaining IPs to reach 50+ indicators
for (let i = 1; i <= 40; i++) {
  const ipTypes = [
    { rep: "malicious", tag: "botnet", src: "Offline-Botnet-Feed", score: 90 },
    { rep: "suspicious", tag: "scanner", src: "Offline-Scanner-Feed", score: 65 },
    { rep: "malicious", tag: "c2", src: "Offline-C2-Tracker", score: 95 },
    { rep: "suspicious", tag: "tor", src: "Offline-Tor-Nodes", score: 70 },
    { rep: "clean", tag: "cdn", src: "Offline-Whitelist", score: 10 }
  ];
  const typeDef = ipTypes[i % ipTypes.length];
  
  OFFLINE_DATASET.push({
    type: "IP",
    value: `${200 + (i % 50)}.${10 + i}.${20 + i}.${100 + i}`,
    reputation: typeDef.rep as any,
    confidence_score: typeDef.score,
    country: ["US", "RU", "CN", "BR", "DE", "NL"][i % 6],
    sources: JSON.stringify([typeDef.src]),
    tags: JSON.stringify([typeDef.tag, `auto-gen-${i}`]),
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    raw_data: JSON.stringify({ note: `Offline dataset generated IP #${i}` }),
  });
}
