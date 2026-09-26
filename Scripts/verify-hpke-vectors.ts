// deno run --allow-read --allow-run --allow-write Scripts/verify-hpke-vectors.ts
const root = new URL("..", import.meta.url).pathname;
const diem = new URL("../../diem-e641a7df16", import.meta.url).pathname;
const fixture = JSON.parse(await Deno.readTextFile(`${root}/Tests/Vectors/device-authority-v2.json`));
const classes = await Deno.makeTempDir({ prefix: "diem-hpke-" });
try {
  const compile = await new Deno.Command("javac", { args: ["-d", classes,
    `${diem}/Android/src/main/java/org/diem/crypto/P256HPKE.java`,
    `${diem}/Android/src/test/java/org/diem/crypto/HPKEVectors.java`],
  }).output();
  if (!compile.success) throw new Error(new TextDecoder().decode(compile.stderr));
  for (const v of fixture.vectors) {
    const run = await new Deno.Command("java", { args: ["-cp", classes, "org.diem.crypto.HPKEVectors",
      v.hpkePrivateKey, v.hpkePublicKey, v.hpkeEncapsulatedKey,
      v.hpkeCiphertext, v.hpkeContext, v.hpkePlaintext],
    }).output();
    if (!run.success) throw new Error(new TextDecoder().decode(run.stderr));
  }
  console.log(`Verified ${fixture.vectors.length} HPKE fixtures with the independent Java receiver.`);
} finally {
  await Deno.remove(classes, { recursive: true });
}
