# TapEnc

Encrypt a short note or daily task list on the phone. Share the ciphertext by NFC tag, QR code, or a `.tapenc` file. Decrypt only with the shared passphrase. No server, no account.

Open `index.html` in a mobile browser (Chrome on Android for NFC).

## Honest limits

Two phones cannot generally dump a custom encrypted file into each other over raw NFC in 2026:

- Android Beam (phone-to-phone NDEF push) is gone
- iOS Core NFC is tag reader/writer, not a general peer-to-phone pipe
- Web NFC is Chrome-on-Android and talks to **tags**, not the other phone

OS-level tap-to-share (Quick Share / AirDrop-style) uses NFC only as a handshake, then moves the file over Wi-Fi Direct. That is the right channel for a `.tapenc` file.

## Practical tap flow with mates

1. Agree a passphrase once (not written on the tag)
2. Type today’s tasks → Encrypt
3. Write an NFC sticker, show the QR, or download `today.tapenc` and send it with AirDrop / Quick Share
4. Mate opens Receive → paste / file / NFC read → Decrypt

Cheap NTAG213 tags hold ~144 bytes. NTAG216 holds ~888. Long lists should go in the file, not on the chip.
