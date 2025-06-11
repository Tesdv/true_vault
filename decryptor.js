import { deriveKey, decryptData } from './crypto.js';

async function unlock() {
  const password = document.getElementById('password').value;

  try {
    const encBundle = await fetch('app.bundle.enc').then(res => res.arrayBuffer());
    const metadata = await fetch('app.bundle.meta.json').then(res => res.json());

    const key = await deriveKey(password, metadata.salt);
    const decrypted = await decryptData(encBundle, key, metadata.iv, metadata.tag);

    const blob = new Blob([decrypted], { type: 'application/javascript' });
    const url = URL.createObjectURL(blob);
    await import(url);
  } catch (e) {
    console.error(e);
    document.getElementById('error').style.display = 'block';
  }
}
