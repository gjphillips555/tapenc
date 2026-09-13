const enc = new TextEncoder();
const dec = new TextDecoder();
const ITER = 210000;
const PREFIX = "TAPENC1.";

const $ = (id) => document.getElementById(id);
const sendStatus = (t, kind) => { const el = $("sendStatus"); el.className = "status " + (kind || ""); el.textContent = t; };
const recvStatus = (t, kind) => { const el = $("recvStatus"); el.className = "status " + (kind || ""); el.textContent = t; };

let lastPayload = "";

function nfcSupported() {
  return "NDEFReader" in window;
}

async function deriveKey(pass, salt) {
  const base = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function b64(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function unb64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function encryptText(text, pass) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(pass, salt);
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text)));
  const packed = new Uint8Array(1 + salt.length + iv.length + cipher.length);
  packed[0] = 1;
  packed.set(salt, 1);
  packed.set(iv, 17);
  packed.set(cipher, 29);
  return PREFIX + b64(packed);
}

async function decryptText(payload, pass) {
  const raw = payload.trim();
  if (!raw.startsWith(PREFIX)) throw new Error("Not a TapEnc payload (missing TAPENC1. prefix).");
  const packed = unb64(raw.slice(PREFIX.length));
  if (packed.length < 30 || packed[0] !== 1) throw new Error("Corrupt or unsupported payload.");
  const salt = packed.slice(1, 17);
  const iv = packed.slice(17, 29);
  const cipher = packed.slice(29);
  const key = await deriveKey(pass, salt);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
  return dec.decode(plain);
}

function loadRemembered() {
  const p = localStorage.getItem("tapenc_pass") || "";
  if (p) {
    $("pass").value = p;
    $("pass2").value = p;
    $("rpass").value = p;
    $("remember").checked = true;
  }
}
function maybeRemember() {
  if ($("remember").checked) localStorage.setItem("tapenc_pass", $("pass").value);
  else localStorage.removeItem("tapenc_pass");
}

$("tabSend").onclick = () => {
  $("tabSend").classList.add("on"); $("tabRecv").classList.remove("on");
  $("sendPane").hidden = false; $("recvPane").hidden = true;
};
$("tabRecv").onclick = () => {
  $("tabRecv").classList.add("on"); $("tabSend").classList.remove("on");
  $("recvPane").hidden = false; $("sendPane").hidden = true;
};

$("togglePass").onclick = () => {
  const show = $("pass").type === "password";
  $("pass").type = $("pass2").type = show ? "text" : "password";
  $("togglePass").textContent = show ? "Hide" : "Show";
};
$("rtogglePass").onclick = () => {
  const show = $("rpass").type === "password";
  $("rpass").type = show ? "text" : "password";
  $("rtogglePass").textContent = show ? "Hide" : "Show";
};

$("msg").addEventListener("input", () => {
  const n = $("msg").value.length;
  let extra = "";
  if (n > 400) extra = " · likely too big for a cheap NFC tag";
  else if (n > 180) extra = " · may need an NTAG216 (888 byte) tag";
  $("sizeHint").textContent = n + " characters" + extra;
});

function enableShare(on) {
  $("btnQr").disabled = !on;
  $("btnCopy").disabled = !on;
  $("btnFile").disabled = !on;
  $("btnNfcWrite").disabled = !on || !nfcSupported();
}

$("btnEncrypt").onclick = async () => {
  try {
    const text = $("msg").value.trim();
    const p1 = $("pass").value;
    const p2 = $("pass2").value;
    if (!text) throw new Error("Write a message first.");
    if (p1.length < 8) throw new Error("Use at least 8 characters for the passphrase.");
    if (p1 !== p2) throw new Error("Passphrases do not match.");
    maybeRemember();
    lastPayload = await encryptText(text, p1);
    $("payloadOut").hidden = false;
    $("payloadOut").textContent = lastPayload;
    enableShare(true);
    const bytes = Math.ceil(lastPayload.length * 0.75);
    sendStatus("Encrypted. Packed size ~" + bytes + " bytes. Share with QR, file, or NFC tag.", "");
    if (!nfcSupported()) {
      $("btnNfcWrite").disabled = true;
    }
  } catch (e) {
    enableShare(false);
    sendStatus(e.message || String(e), "err");
  }
};

$("btnCopy").onclick = async () => {
  await navigator.clipboard.writeText(lastPayload);
  sendStatus("Payload copied.", "");
};

$("btnFile").onclick = () => {
  const blob = new Blob([lastPayload], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "today.tapenc";
  a.click();
  URL.revokeObjectURL(a.href);
  sendStatus("Downloaded today.tapenc — send that file however you like (AirDrop, Quick Share, USB).", "");
};

$("btnQr").onclick = async () => {
  $("qrbox").innerHTML = "";
  if (typeof QRCode === "undefined") {
    sendStatus("QR library failed to load. Copy the payload or download the file instead.", "warn");
    return;
  }
  if (lastPayload.length > 1200) {
    sendStatus("Payload is large for a reliable QR. Download the file or shorten the message.", "warn");
  }
  try {
    const canvas = document.createElement("canvas");
    await QRCode.toCanvas(canvas, lastPayload, { errorCorrectionLevel: "M", width: 280, margin: 1 });
    $("qrbox").appendChild(canvas);
    sendStatus("Mate opens Receive, scans this QR (or pastes the payload), then decrypts.", "");
  } catch (e) {
    sendStatus("Could not draw QR: " + e.message, "err");
  }
};

$("btnNfcWrite").onclick = async () => {
  if (!nfcSupported()) {
    sendStatus("Web NFC is only in Chrome on Android, and only writes physical tags — not the other phone.", "warn");
    return;
  }
  try {
    sendStatus("Hold the phone to a writable NFC tag…", "");
    const writer = new NDEFReader();
    await writer.write({
      records: [
        { recordType: "mime", mediaType: "application/vnd.tapenc", data: lastPayload },
        { recordType: "text", data: "TapEnc encrypted payload. Open tapenc to decrypt." }
      ]
    });
    sendStatus("Wrote encrypted payload to the tag. Mate taps the same tag on Receive → Read NFC.", "");
  } catch (e) {
    sendStatus("NFC write failed: " + (e.message || e), "err");
  }
};

$("btnDecrypt").onclick = async () => {
  try {
    const pass = $("rpass").value;
    const payload = $("rin").value.trim();
    if (!payload) throw new Error("Paste a payload, open a file, or read a tag first.");
    if (!pass) throw new Error("Enter the shared passphrase.");
    const plain = await decryptText(payload, pass);
    $("plainOut").hidden = false;
    $("plainOut").textContent = plain;
    recvStatus("Decrypted on this device only.", "");
  } catch (e) {
    $("plainOut").hidden = true;
    recvStatus(e.message || String(e), "err");
  }
};

$("fileIn").onchange = async (ev) => {
  const f = ev.target.files && ev.target.files[0];
  if (!f) return;
  $("rin").value = (await f.text()).trim();
  recvStatus("Loaded " + f.name + ". Enter passphrase and decrypt.", "");
};

$("btnNfcRead").onclick = async () => {
  if (!nfcSupported()) {
    recvStatus("Web NFC is Chrome-on-Android only. On iPhone, paste the payload, open the .tapenc file, or scan the QR with the camera + paste.", "warn");
    return;
  }
  try {
    recvStatus("Hold the phone to the tag…", "");
    const reader = new NDEFReader();
    await reader.scan();
    reader.onreadingerror = () => recvStatus("Could not read that tag.", "err");
    reader.onreading = (event) => {
      let found = "";
      for (const rec of event.message.records) {
        if (rec.recordType === "mime" && rec.mediaType === "application/vnd.tapenc") {
          found = dec.decode(rec.data);
        } else if (rec.recordType === "text" && !found) {
          const t = dec.decode(rec.data);
          if (t.startsWith(PREFIX)) found = t;
        } else if (rec.recordType === "url" && !found) {
          const t = dec.decode(rec.data);
          if (t.startsWith(PREFIX)) found = t;
        }
      }
      if (!found) {
        for (const rec of event.message.records) {
          try {
            const t = dec.decode(rec.data);
            if (t.includes(PREFIX)) found = t.slice(t.indexOf(PREFIX));
          } catch (_) {}
        }
      }
      if (!found) {
        recvStatus("Tag had no TapEnc payload.", "err");
        return;
      }
      $("rin").value = found.trim();
      recvStatus("Got encrypted payload from tag. Decrypt it.", "");
    };
  } catch (e) {
    recvStatus("NFC read failed: " + (e.message || e), "err");
  }
};

loadRemembered();
if (!nfcSupported()) {
  $("btnNfcWrite").title = "Needs Chrome on Android + a physical NFC tag";
  $("btnNfcRead").title = "Needs Chrome on Android + a physical NFC tag";
}
