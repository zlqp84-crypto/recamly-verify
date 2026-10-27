// Recamly Stamp 진본 확인. 파일은 서버로 보내지 않고 이 브라우저 안에서만 계산한다.
// 앱 쪽 봉인 방식: android/.../Proof.kt
//   [원본][u32 전체 길이]["free"][증명서 JSON][u32 JSON 길이]["RCMLPRF1"]
import * as asn1js from 'https://cdn.jsdelivr.net/npm/asn1js@3.0.5/+esm';
import * as pkijs from 'https://cdn.jsdelivr.net/npm/pkijs@3.2.4/+esm';
import { GOOGLE_ROOTS, FREETSA_CA } from './roots.js';

const MAGIC = 'RCMLPRF1';
const PACKAGE = 'com.recamly.recamly_stamp';
const CHALLENGE = 'recamly-proof-v1';
const ATTESTATION_OID = '1.3.6.1.4.1.11129.2.1.17';

// 앱 서명 인증서의 SHA-256. 키 증명서에 "이 키를 만든 앱의 서명"으로 들어간다.
// 플레이 스토어로 배포하면 구글 앱 서명 키가 추가된다 → 그때 여기에 넣는다.
export const APP_SIGNERS = {
  // 개발 PC의 디버그 키(~/.android/debug.keystore). 출시 전에 정식 서명 키로 바꾼다.
  'aa3c624a11aa6714d17020b433f16a98a59239b7a413470b986970425724b6ce': '개발용 빌드',
};

const enc = new TextEncoder();
const dec = new TextDecoder();
const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const sha256 = async (u8) => new Uint8Array(await crypto.subtle.digest('SHA-256', u8));
const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

function pemToDer(pem) {
  return b64(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''));
}
function cert(der) {
  return pkijs.Certificate.fromBER(der);
}

/** 파일 끝의 증명서를 떼어 낸다. 없으면 null. */
export function extract(buf) {
  const u8 = new Uint8Array(buf);
  const n = u8.length;
  if (n < 20 || dec.decode(u8.subarray(n - 8)) !== MAGIC) return null;
  const dv = new DataView(u8.buffer, u8.byteOffset, n);
  const jsonLen = dv.getUint32(n - 12);
  const total = 8 + jsonLen + 12;
  if (total > n || dv.getUint32(n - total) !== total) return null;
  if (dec.decode(u8.subarray(n - total + 4, n - total + 8)) !== 'free') return null;
  const proof = JSON.parse(dec.decode(u8.subarray(n - 12 - jsonLen, n - 12)));
  return { proof, content: u8.subarray(0, n - total) };
}

/** 안드로이드 서명(DER)을 WebCrypto가 받는 r||s 64바이트로. */
function derToRaw(der) {
  const seq = asn1js.fromBER(der).result;
  const part = (i) => {
    let v = new Uint8Array(seq.valueBlock.value[i].valueBlock.valueHexView);
    while (v.length > 32 && v[0] === 0) v = v.subarray(1);
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const raw = new Uint8Array(64);
  raw.set(part(0), 0);
  raw.set(part(1), 32);
  return raw;
}

/** 키 증명 확장(KeyDescription)에서 필요한 것만 읽는다. */
function keyDescription(leaf) {
  const ext = (leaf.extensions || []).find((e) => e.extnID === ATTESTATION_OID);
  if (!ext) return null;
  const kd = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView).result.valueBlock.value;
  const level = ['Software', 'TrustedEnvironment', 'StrongBox'][kd[1].valueBlock.valueDec];
  const challenge = dec.decode(new Uint8Array(kd[4].valueBlock.valueHexView));
  const lists = [kd[6], kd[7]]; // softwareEnforced, hardwareEnforced
  const tagged = (n) => {
    for (const l of lists) {
      for (const item of l.valueBlock.value) {
        if (item.idBlock.tagNumber === n) return item.valueBlock.value[0];
      }
    }
    return null;
  };
  let app = null;
  const appId = tagged(709); // attestationApplicationId
  if (appId) {
    const a = asn1js.fromBER(appId.valueBlock.valueHexView).result.valueBlock.value;
    const packages = a[0].valueBlock.value.map((p) =>
      dec.decode(new Uint8Array(p.valueBlock.value[0].valueBlock.valueHexView)),
    );
    const digests = a[1].valueBlock.value.map((d) => hex(new Uint8Array(d.valueBlock.valueHexView)));
    app = { packages, digests };
  }
  let root = null;
  const rot = tagged(704); // rootOfTrust
  if (rot) {
    const r = rot.valueBlock.value;
    root = {
      deviceLocked: r[1].valueBlock.value,
      bootState: ['Verified', 'SelfSigned', 'Unverified', 'Failed'][r[2].valueBlock.valueDec],
    };
  }
  return { level, challenge, app, root };
}

async function revoked(certs) {
  try {
    const r = await fetch('https://android.googleapis.com/attestation/status', { cache: 'no-store' });
    const list = (await r.json()).entries || {};
    return certs.some((c) => list[hex(new Uint8Array(c.serialNumber.valueBlock.valueHexView)).replace(/^0+/, '')]);
  } catch {
    return null; // 확인 못 함 (오프라인 등)
  }
}

async function checkTimestamp(proof, sig) {
  if (!proof.tsr) return null;
  const resp = pkijs.TimeStampResp.fromBER(b64(proof.tsr));
  const signed = new pkijs.SignedData({ schema: resp.timeStampToken.content });
  const tst = pkijs.TSTInfo.fromBER(signed.encapContentInfo.eContent.valueBlock.valueHexView);
  const imprint = new Uint8Array(tst.messageImprint.hashedMessage.valueBlock.valueHexView);
  const matches = same(imprint, await sha256(sig));
  let trusted = false;
  try {
    // data: 시간 증명을 받은 원래 데이터(서명). pkijs가 TSTInfo의 지문과 대조하고,
    // TSA 서명과 FreeTSA 루트까지의 인증서 사슬도 확인한다.
    const v = await signed.verify({
      signer: 0,
      trustedCerts: [cert(pemToDer(FREETSA_CA))],
      checkChain: true,
      extendedMode: true,
      data: sig.slice().buffer,
    });
    trusted = v.signatureVerified === true;
  } catch {
    trusted = false;
  }
  return { ok: matches && trusted, matches, trusted, time: tst.genTime, by: proof.tsa };
}

/**
 * 결과: { verdict: 'original' | 'modified' | 'none' | 'unknown', checks: [...], claim, ... }
 * checks 항목: { id, ok: true|false|null(확인 못 함), text }
 */
export async function verify(buf) {
  const found = extract(buf);
  if (!found) return { verdict: 'none', checks: [] };
  const { proof, content } = found;
  const claim = JSON.parse(proof.claim);
  const checks = [];
  const add = (id, ok, text) => checks.push({ id, ok, text });

  // 1. 파일이 바뀌지 않았나
  const hashOk = hex(await sha256(content)) === claim.sha256;
  add('hash', hashOk, hashOk ? '파일이 촬영 뒤 한 글자도 바뀌지 않았어요.' : '파일 내용이 촬영 때와 달라요.');

  // 2. 서명 + 키 증명서 사슬
  const certs = proof.chain.map((c) => cert(b64(c)));
  const sig = b64(proof.sig);
  let sigOk = false;
  if (certs.length) {
    try {
      const spki = certs[0].subjectPublicKeyInfo.toSchema().toBER(false);
      const key = await crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      sigOk = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, derToRaw(sig), enc.encode(proof.claim));
    } catch {
      sigOk = false;
    }
  }
  add('sig', sigOk, sigOk ? '촬영 정보와 파일 지문에 폰 보안 칩의 서명이 맞아요.' : '서명이 맞지 않아요.');

  let chainOk = certs.length > 1;
  for (let i = 0; chainOk && i < certs.length - 1; i++) {
    try {
      chainOk = await certs[i].verify(certs[i + 1]);
    } catch {
      chainOk = false;
    }
  }
  const top = certs.at(-1);
  const rootKeys = GOOGLE_ROOTS.map((p) => hex(new Uint8Array(cert(pemToDer(p)).subjectPublicKeyInfo.toSchema().toBER(false))));
  const googleRoot = !!top && rootKeys.includes(hex(new Uint8Array(top.subjectPublicKeyInfo.toSchema().toBER(false))));
  const chainTrusted = chainOk && googleRoot;
  add('chain', chainTrusted, chainTrusted ? '서명 키가 구글이 보증하는 폰 보안 칩 안에서 만들어졌어요.' : '서명 키를 구글 보안 칩 증명으로 확인할 수 없어요.');

  const kd = certs.length ? keyDescription(certs[0]) : null;
  const pkgOk = !!kd?.app?.packages.includes(PACKAGE) && kd.challenge === CHALLENGE;
  const signer = kd?.app?.digests.map((d) => APP_SIGNERS[d]).find(Boolean) || null;
  add(
    'app',
    pkgOk && !!signer,
    !pkgOk
      ? 'Recamly Stamp 앱이 만든 키가 아니에요.'
      : signer
        ? `Recamly Stamp 앱(${signer})이 찍었어요.`
        : 'Recamly Stamp 이름의 앱이지만, 정식 배포본의 서명이 아니에요.',
  );
  const deviceOk = kd?.root ? kd.root.deviceLocked && kd.root.bootState === 'Verified' : null;
  add(
    'device',
    deviceOk,
    deviceOk === null
      ? '폰 변조 여부를 확인할 수 없어요.'
      : deviceOk
        ? '루팅·변조되지 않은 폰에서 찍었어요.'
        : '루팅되거나 잠금이 풀린 폰에서 찍었어요.',
  );
  const rev = await revoked(certs);
  if (rev === true) add('revoked', false, '구글이 이 폰의 보안 칩 인증서를 폐기했어요.');

  // 3. 공공 시간 증명
  const ts = await checkTimestamp(proof, sig);
  add(
    'time',
    ts ? ts.ok : null,
    !ts
      ? '공공 시간 증명이 없어요 (찍을 때 인터넷이 안 됐을 수 있어요). 촬영 시각은 폰 기록만 있어요.'
      : ts.ok
        ? `공공 시간 증명(${ts.by})으로 ${fmtTime(ts.time)}에 이 파일이 있었음이 확인돼요.`
        : '공공 시간 증명이 맞지 않아요.',
  );

  const tampered = !hashOk || !sigOk;
  const strong = chainTrusted && pkgOk && !!signer && rev !== true;
  return {
    verdict: tampered ? 'modified' : strong ? 'original' : 'unknown',
    checks,
    claim,
    level: kd?.level || null,
    timestamp: ts,
  };
}

export function fmtTime(d) {
  return d.toLocaleString('ko-KR', { timeZone: 'Asia/Seoul', hour12: false }) + ' (한국 시간)';
}
