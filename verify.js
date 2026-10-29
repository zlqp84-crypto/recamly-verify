// Recamly Stamp 진본 확인. 파일은 서버로 보내지 않고 이 브라우저 안에서만 계산한다.
// 앱 쪽 봉인 방식: android/.../Proof.kt
//   [원본][u32 전체 길이]["free"][증명서 JSON][u32 JSON 길이]["RCMLPRF1"]
import * as asn1js from 'https://cdn.jsdelivr.net/npm/asn1js@3.0.5/+esm';
import * as pkijs from 'https://cdn.jsdelivr.net/npm/pkijs@3.2.4/+esm';
import { GOOGLE_ROOTS, FREETSA_CA, DIGICERT_G4 } from './roots.js';

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
    const roots = [cert(pemToDer(DIGICERT_G4)), cert(pemToDer(FREETSA_CA))];
    // DigiCert는 루트를 다른 옛 루트가 보증한 사본으로도 넣어 보내는데, 그 사본으로
    // 길을 찾다 막히면 확인이 실패한다. 우리가 가진 루트와 이름이 같은 인증서는 뺀다.
    const name = (c) => c.subject.toString();
    signed.certificates = (signed.certificates || []).filter(
      (c) => !roots.some((r) => name(r) === name(c)),
    );
    // data: 시간 증명을 받은 원래 데이터(서명). pkijs가 TSTInfo의 지문과 대조하고,
    // TSA 서명과 믿는 루트(DigiCert, FreeTSA)까지의 인증서 사슬도 확인한다.
    const v = await signed.verify({
      signer: 0,
      trustedCerts: roots,
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
export async function verify(buf, lang = 'ko') {
  const t = (ko, en) => (lang === 'en' ? en : ko);
  const found = extract(buf);
  if (!found) return { verdict: 'none', checks: [] };
  const { proof, content } = found;
  const claim = JSON.parse(proof.claim);
  const checks = [];
  const add = (id, ok, text) => checks.push({ id, ok, text });

  // 1. 파일이 바뀌지 않았나
  const hashOk = hex(await sha256(content)) === claim.sha256;
  add('hash', hashOk, hashOk
    ? t('파일이 촬영 뒤 한 글자도 바뀌지 않았어요.', 'Not a single byte has changed since capture.')
    : t('파일 내용이 촬영 때와 달라요.', 'The file content differs from capture.'));

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
  add('sig', sigOk, sigOk
    ? t('촬영 정보와 파일 지문에 폰 보안 칩의 서명이 맞아요.', "The phone security chip's signature matches the capture info and file fingerprint.")
    : t('서명이 맞지 않아요.', 'The signature does not match.'));

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
  add('chain', chainTrusted, chainTrusted
    ? t('서명 키가 구글이 보증하는 폰 보안 칩 안에서 만들어졌어요.', 'The signing key was created inside a phone security chip certified by Google.')
    : t('서명 키를 구글 보안 칩 증명으로 확인할 수 없어요.', "The signing key can't be confirmed by Google's security chip attestation."));

  const kd = certs.length ? keyDescription(certs[0]) : null;
  const pkgOk = !!kd?.app?.packages.includes(PACKAGE) && kd.challenge === CHALLENGE;
  const signer = kd?.app?.digests.map((d) => APP_SIGNERS[d]).find(Boolean) || null;
  add(
    'app',
    pkgOk && !!signer,
    !pkgOk
      ? t('Recamly Stamp 앱이 만든 키가 아니에요.', 'The key was not made by the Recamly Stamp app.')
      : signer
        ? t(`Recamly Stamp 앱(${signer})이 찍었어요.`, `Taken with the Recamly Stamp app (${signer === '개발용 빌드' ? 'development build' : signer}).`)
        : t('Recamly Stamp 이름의 앱이지만, 정식 배포본의 서명이 아니에요.', 'An app named Recamly Stamp, but not signed as an official release.'),
  );
  const deviceOk = kd?.root ? kd.root.deviceLocked && kd.root.bootState === 'Verified' : null;
  add(
    'device',
    deviceOk,
    deviceOk === null
      ? t('폰 변조 여부를 확인할 수 없어요.', "Can't check whether the phone was tampered with.")
      : deviceOk
        ? t('루팅·변조되지 않은 폰에서 찍었어요.', 'Taken on a phone that is not rooted or tampered with.')
        : t('루팅되거나 잠금이 풀린 폰에서 찍었어요.', 'Taken on a rooted or unlocked phone.'),
  );
  const rev = await revoked(certs);
  if (rev === true) add('revoked', false, t('구글이 이 폰의 보안 칩 인증서를 폐기했어요.', "Google has revoked this phone's security chip certificate."));

  // 3. 공공 시간 증명
  const ts = await checkTimestamp(proof, sig);
  add(
    'time',
    ts ? ts.ok : null,
    !ts
      ? t('공공 시간 증명이 없어요 (찍을 때 인터넷이 안 됐을 수 있어요). 촬영 시각은 폰 기록만 있어요.', 'No public timestamp (maybe no internet at capture). The capture time is from the phone only.')
      : ts.ok
        ? t(`공공 시간 증명(${ts.by})으로 ${fmtTime(ts.time)}에 이 파일이 있었음이 확인돼요.`, `A public timestamp (${ts.by}) confirms this file existed at ${fmtTime(ts.time, 'en')}.`)
        : t('공공 시간 증명이 맞지 않아요.', 'The public timestamp does not match.'),
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

export function fmtTime(d, lang = 'ko') {
  if (lang === 'en') return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
  return d.toLocaleString('ko-KR', { timeZone: 'Asia/Seoul', hour12: false }) + ' (한국 시간)';
}

const VERDICT = {
  original: ['원본이 맞아요', 'Recamly Stamp로 찍은 뒤 바뀌지 않은 원본 파일이에요.'],
  modified: ['수정된 파일이에요', '촬영 뒤에 내용이 바뀌었어요. 아래 촬영 정보는 믿을 수 없어요.'],
  unknown: ['일부만 확인됐어요', '파일은 바뀌지 않았지만, 찍은 앱이나 폰을 끝까지 확인하지 못했어요. 아래 항목을 보세요.'],
  none: ['진본 증명서가 없어요', 'Recamly Stamp 원본이 아니거나, 압축·편집되면서 증명서가 지워진 파일이에요.'],
};
const VERDICT_EN = {
  original: ['This is the original', 'An original file, unchanged since it was taken with Recamly Stamp.'],
  modified: ['This file was modified', 'The content changed after capture. The capture info below cannot be trusted.'],
  unknown: ['Partly verified', 'The file is unchanged, but the app or phone could not be fully verified. See the items below.'],
  none: ['No proof certificate', 'Not a Recamly Stamp original, or the certificate was removed by compression or editing.'],
};
// 전후 비교 사진: 원본 2장(시공 전·후)을 나란히 붙여 앱이 만든 사진. 증명서에 원본 2장의 지문이 있다.
const COMPARE_VERDICT = {
  original: ['전후 비교 사진이 맞아요', 'Recamly Stamp가 아래 원본 2장으로 만든 뒤 바뀌지 않은 비교 사진이에요. 각 원본도 이 페이지에서 확인할 수 있어요.'],
};
const COMPARE_VERDICT_EN = {
  original: ['This before/after photo is genuine', 'A comparison photo made by Recamly Stamp from the two originals below, unchanged since. Each original can be verified too.'],
};
const LEVEL = { StrongBox: '별도 보안 칩 (StrongBox, 가장 강함)', TrustedEnvironment: '보안 영역 (TEE)', Software: '소프트웨어 (약함)' };
const LEVEL_EN = { StrongBox: 'Dedicated security chip (StrongBox, strongest)', TrustedEnvironment: 'Secure area (TEE)', Software: 'Software (weak)' };

/**
 * verify() 결과를 사람이 읽는 글로 바꾼다. 이 페이지와 앱의 "진본 확인" 화면이
 * 같이 써서, 둘의 문구가 늘 같다.
 * 결과: { verdict, title, body, checks: [{ ok, text }], rows: [{ label, value, hash?, link? }] }
 *   hash: 고정폭 글꼴로 보일 지문, link: 누르면 여는 주소(지도).
 */
export function describe(r, fileName, lang = 'ko') {
  const en = lang === 'en';
  const t = (ko, e) => (en ? e : ko);
  const cmp = r.claim?.kind === 'compare' ? r.claim.info?.compare : null;
  const [title, body] = (cmp && (en ? COMPARE_VERDICT_EN : COMPARE_VERDICT)[r.verdict]) || (en ? VERDICT_EN : VERDICT)[r.verdict];
  const rows = [];
  const i = r.claim?.info;
  if (i && r.verdict !== 'modified') {
    const row = (label, value, extra) => rows.push({ label, value, ...extra });
    row(t('파일', 'File'), fileName);
    row(
      t('종류', 'Type'),
      cmp
        ? t('전후 비교 사진 (원본 2장을 나란히 붙임)', 'Before/after photo (two originals side by side)')
        : r.claim.kind === 'video'
          ? t('영상 (녹화 시작 시각)', 'Video (recording start time)')
          : t('사진', 'Photo'),
    );
    row(
      cmp ? t('시공 후 촬영', 'After photo taken') : t('촬영 시각', 'Taken at'),
      `${i.local}${i.zone ? ' ' + i.zone : ''} · ${i.timeVerified ? t('인터넷 표준시로 맞춘 시계', 'clock synced to internet time') : t('폰 시계', 'phone clock')}`,
    );
    if (cmp) {
      for (const [label, s] of [[t('시공 전 원본', 'Before original'), cmp.before], [t('시공 후 원본', 'After original'), cmp.after]]) {
        if (s) row(label, [s.local, s.memo, s.name].filter(Boolean).join(' · '), { hash: s.sha256 || undefined });
      }
    }
    if (i.site) row(t('현장', 'Site'), i.site);
    if (i.memo) row(t('메모', 'Memo'), i.memo);
    if (r.timestamp?.ok) {
      const gap = Math.round((r.timestamp.time.getTime() - i.utcMs) / 1000);
      row(
        t('공공 시간 증명', 'Public timestamp'),
        en
          ? `${fmtTime(r.timestamp.time, 'en')} (${Math.abs(gap)} s ${gap >= 0 ? 'after' : 'before'} capture record)`
          : `${fmtTime(r.timestamp.time)} (촬영 기록 ${gap >= 0 ? gap + '초 뒤' : -gap + '초 앞'})`,
      );
    }
    if (i.latitude != null) {
      const ll = `${i.latitude.toFixed(6)}, ${i.longitude.toFixed(6)}`;
      const acc = i.accuracyMeters != null ? t(` (오차 약 ${Math.round(i.accuracyMeters)}m)`, ` (±${Math.round(i.accuracyMeters)} m)`) : '';
      row(t('좌표', 'Coordinates'), ll + acc, { link: `https://www.google.com/maps?q=${ll.replace(' ', '')}` });
    } else {
      row(t('좌표', 'Coordinates'), t('없음 (위치를 못 잡은 채로 찍음)', 'None (taken without a location fix)'));
    }
    if (i.address) {
      row(
        t('주소', 'Address'),
        i.address +
          (i.addressChosen
            ? t(' — GPS 오차 안의 후보 중 촬영자가 고름', ' — chosen by the photographer among candidates within GPS accuracy')
            : t(' — GPS로 자동', ' — automatic from GPS')),
      );
    }
    row(t('기기', 'Device'), r.claim.device);
    if (r.level) row(t('서명 보관', 'Key storage'), (en ? LEVEL_EN : LEVEL)[r.level] || r.level);
    row(t('앱 버전', 'App version'), r.claim.appVersion);
    // PDF 보고서의 "파일 지문"과 같은 값 (원본 파일의 SHA-256).
    row(t('파일 지문', 'File fingerprint'), '', { hash: r.claim.sha256 });
  }
  return {
    verdict: r.verdict,
    title,
    body,
    checks: r.checks.map(({ ok, text }) => ({ ok, text })),
    rows,
  };
}
