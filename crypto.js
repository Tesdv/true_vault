export async function deriveKey(password, saltB64) {
  const enc = new TextEncoder();
  const pwKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    pwKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function decryptData(encData, key, ivB64, tagB64) {
  const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
  const tag = Uint8Array.from(atob(tagB64), c => c.charCodeAt(0));

  const fullData = new Uint8Array(encData);
  const cipherData = new Uint8Array([...fullData, ...tag]);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    cipherData
  );

  return new TextDecoder().decode(decrypted);
}
