import {decode, encode} from './cbor.js';

const check = (value, label) => { if(!value) throw new Error(label); };
async function rejects(action) {
  try { await action(); } catch { return; }
  throw new Error('Expected key-file rejection');
}

export async function exerciseKeyFiles(diem) {
  const {file} = await (await fetch(new URL('./key-file-native.json', import.meta.url))).json();
  const opened = await diem.keyFiles.unlock(file, 'x');
  check(opened.contents.domain === 'keys.example', 'Native HPKE file opens in browser');
  check(opened.contents.identity && opened.contents.device, 'Both key roles restored');
  check(decode(file)[0] === 14 && decode(file)[5] === 600000, 'Canonical CBOR key-file header');
  const browserFile = await opened.session.seal(opened.contents);
  const roundTrip = await diem.keyFiles.unlock(browserFile, 'x');
  check(roundTrip.contents.profile === opened.contents.profile, 'Profile preserved');
  check(roundTrip.contents.identity.privateKey === opened.contents.identity.privateKey, 'Recovery authority preserved');
  roundTrip.session.destroy();
  await rejects(() => roundTrip.session.open(browserFile));
  await rejects(() => diem.keyFiles.create(''));
  await rejects(() => diem.keyFiles.unlock(file, 'wrong'));
  await rejects(() => diem.keyFiles.unlock(new TextEncoder().encode('{"version":1}'), 'x'));
  for(const field of [2, 3, 7, 8]) {
    const tampered = decode(file);
    tampered[field][tampered[field].length - 1] ^= 1;
    await rejects(() => opened.session.open(encode(tampered)));
  }
  const extended = decode(file); extended[99] = 'unauthenticated header';
  await rejects(() => opened.session.open(encode(extended)));
  const expensive = decode(file); expensive[5] = 2 ** 32;
  await rejects(() => diem.keyFiles.unlock(encode(expensive), 'x'));
  for(const role of ['identity', 'device']) {
    const value = {...opened.contents, [role]: undefined};
    const single = await opened.session.seal(value);
    check(!(await opened.session.open(single))[role], 'Single-role file preserves authority boundary');
  }
  const mismatched = {...opened.contents, identity: await diem.generateSigningKey()};
  await rejects(() => opened.session.seal(mismatched));
  opened.session.destroy();
  return Array.from(browserFile);
}
