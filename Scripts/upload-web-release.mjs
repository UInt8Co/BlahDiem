import {spawnSync} from 'node:child_process';
import {readdir, stat} from 'node:fs/promises';
import {resolve} from 'node:path';

const setting = 'WEB_RELEASE_S3_TARGETS';

function readTargets(value) {
  if(!value?.trim()) return [];
  let targets;
  // JSON parser errors can include pieces of the secret.
  try { targets = JSON.parse(value); }
  catch { throw new Error(`${setting} must be a JSON array.`); }
  if(!Array.isArray(targets)) throw new Error(`${setting} must be a JSON array.`);
  return targets.map((target, index) => {
    const invalid = field => { throw new Error(`${setting}[${index}]: invalid ${field}.`); };
    if(!target || typeof target !== 'object' || Array.isArray(target)) invalid('target');
    const fields = ['bucket', 'prefix', 'region', 'endpointUrl', 'accessKeyId', 'secretAccessKey', 'sessionToken'];
    if(Object.keys(target).some(key => !fields.includes(key))) invalid('field name');
    for(const field of fields) {
      if(target[field] !== undefined && (typeof target[field] !== 'string' || /[\x00-\x1f\x7f]/.test(target[field]))) invalid(field);
    }
    for(const field of ['bucket', 'accessKeyId', 'secretAccessKey']) {
      if(!target[field]?.trim()) invalid(field);
    }
    if(!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(target.bucket)) invalid('bucket');
    const prefix = (target.prefix ?? '').replace(/^\/+|\/+$/g, '');
    if(prefix && prefix.split('/').some(part => !part || part === '.' || part === '..')) invalid('prefix');
    const region = target.region ?? 'us-east-1';
    if(!/^[a-z0-9-]+$/.test(region)) invalid('region');
    if(target.endpointUrl !== undefined) {
      let endpoint;
      try { endpoint = new URL(target.endpointUrl); } catch { invalid('endpointUrl'); }
      if(!['https:', 'http:'].includes(endpoint.protocol) || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) invalid('endpointUrl');
    }
    return {...target, prefix, region};
  });
}

async function main() {
  const targets = readTargets(process.env[setting]);
  if(!targets.length) {
    console.log(`${setting} is empty; skipping S3 uploads.`);
    return;
  }
  const [artifact, tag] = process.argv.slice(2);
  if(process.argv.length !== 4 || !artifact || !/^\d{8}-[a-f0-9]{4}$/.test(tag ?? '')) {
    throw new Error('Usage: node Scripts/upload-web-release.mjs <artifact directory> <YYYYMMDD-sha4>');
  }
  const dist = resolve(artifact, 'dist');
  const entries = await readdir(dist, {withFileTypes: true});
  if(entries.some(entry => !entry.isFile())) throw new Error('Expected release files in artifact/dist.');
  // S3 serves the plain assets; compression belongs to the CDN. Archives and
  // precompressed variants remain available from the GitHub release.
  const files = entries.filter(entry => !/\.(gz|br)$/.test(entry.name))
    .map(entry => ({name: entry.name, path: resolve(dist, entry.name)}));
  if(!files.length) throw new Error('Expected uncompressed release files in artifact/dist.');
  for(const file of files) {
    const info = await stat(file.path);
    if(!info.isFile() || !info.size) throw new Error(`Missing or empty release asset: ${file.name}`);
  }

  // Use only this target's AWS settings. Never pass the JSON secret or another
  // target's credentials to the CLI, and never put credentials in command arguments.
  const baseEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('AWS_') && key !== setting));
  for(const [index, target] of targets.entries()) {
    const env = {...baseEnv, AWS_ACCESS_KEY_ID: target.accessKeyId,
      AWS_SECRET_ACCESS_KEY: target.secretAccessKey, AWS_SESSION_TOKEN: target.sessionToken ?? '',
      AWS_CONFIG_FILE: '/dev/null', AWS_SHARED_CREDENTIALS_FILE: '/dev/null',
      AWS_EC2_METADATA_DISABLED: 'true', AWS_RETRY_MODE: 'standard', AWS_MAX_ATTEMPTS: '4',
      AWS_REQUEST_CHECKSUM_CALCULATION: 'when_required'};
    const destination = `s3://${target.bucket}/${target.prefix ? target.prefix + '/' : ''}${tag}/`;
    console.log(`Uploading ${files.length} release assets to S3 target ${index + 1}.`);
    for(const file of files) {
      const contentType = {js: 'text/javascript', wasm: 'application/wasm', json: 'application/json'}[file.name.split('.').at(-1)] ?? 'text/plain';
      const args = ['s3', 'cp', file.path, destination + file.name, '--only-show-errors',
        '--region', target.region, '--content-type', contentType,
        ...(target.endpointUrl ? ['--endpoint-url', target.endpointUrl] : [])];
      // CLI errors can echo endpoints or credentials from the JSON secret.
      // Report the target and file instead of forwarding raw output.
      const result = spawnSync('aws', args, {env, encoding: 'utf8', timeout: 300_000});
      if(result.error?.code === 'ENOENT') throw new Error('Install the AWS CLI to upload release assets.');
      if(result.error || result.status !== 0) throw new Error(`S3 target ${index + 1}: upload failed for ${file.name} (exit ${result.status ?? 'unavailable'}).`);
    }
  }
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
