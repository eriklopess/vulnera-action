import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

const exec = promisify(execFile);
const out = join(process.env.RUNNER_TEMP || '/tmp', `vulnera-${process.env.VULNERA_SCAN_ID}`);
const scanners = (process.env.VULNERA_SCANNERS || 'secrets,sca,sast,iac').split(',').map((x) => x.trim()).filter(Boolean);
const allow = process.env.VULNERA_ALLOW_INGESTION === 'true';
const apiBase = (() => {
  const raw = String(process.env.VULNERA_API_URL ?? '').trim().replace(/\/+$/, '');
  if (!raw) throw new Error('VULNERA_API_URL não configurada');
  return /\/api$/i.test(raw) ? raw : `${raw}/api`;
})();
const command = async (bin, args, output, timeout) => { try { await exec(bin, args, { cwd: process.env.GITHUB_WORKSPACE, maxBuffer: 8 * 1024 * 1024, timeout }); } catch (error) { if (error.code !== 1) throw error; } return readFile(output, 'utf8').then(JSON.parse).catch(() => Array.isArray(output) ? output : []); };
const records = (scanner, raw) => {
  if (scanner === 'SECRETS') return Array.isArray(raw) ? raw : [];
  if (scanner === 'SAST') return Array.isArray(raw?.results) ? raw.results : [];
  if (scanner === 'IAC') return Array.isArray(raw?.results?.failed_checks) ? raw.results.failed_checks : [];
  if (!Array.isArray(raw?.results)) return [];
  return raw.results.flatMap((result) => (result.packages ?? []).flatMap((pkg) => (pkg.vulnerabilities ?? []).map((vulnerability) => ({ ...vulnerability, package: pkg.package ?? pkg, source: result.source ?? result.file, manifestPath: result.source ?? result.file }))));
};
const dependencies = (raw) => (Array.isArray(raw?.results) ? raw.results : []).flatMap((result) => (result.packages ?? []).map((item) => ({ manifestPath: result.source ?? result.file ?? 'unknown', ecosystem: item.ecosystem ?? 'unknown', packageName: item.package?.name ?? item.name ?? 'unknown', packageVersion: item.package?.version ?? item.version ?? 'unknown', packageUrl: item.package?.purl, direct: true, development: false }))).slice(0, 20_000);
const REDACTED_KEYS = new Set(['secret', 'secrets', 'match', 'matched', 'raw', 'code', 'codesnippet', 'lines', 'contents', 'content']);
const sanitize = (value, depth = 0) => {
  if (depth > 8 || value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.slice(0, 10_000).map((item) => sanitize(item, depth + 1));
  return Object.fromEntries(Object.entries(value).filter(([key]) => !REDACTED_KEYS.has(key.toLowerCase())).map(([key, item]) => [key, sanitize(item, depth + 1)]));
};
const normalized = (scanner, toolVersion, raw) => records(scanner, raw).slice(0, 10_000).map((item) => {
  const location = item.location ?? item.file_location ?? {};
  const filePath = item.file ?? item.path ?? location.path ?? item.File ?? item.resource ?? undefined;
  const startLine = Number(item.start_line ?? location.start_line ?? item.StartLine ?? 1);
  const ruleId = String(item.RuleID ?? item.check_id ?? item.checkId ?? item.rule_id ?? item.id ?? item.vulnerability?.id ?? 'unknown-rule').slice(0, 256);
  const title = String(item.Description ?? item.message ?? item.reason ?? item.name ?? item.vulnerability?.summary ?? ruleId).slice(0, 512);
  const fingerprint = createHash('sha256').update([process.env.VULNERA_REPOSITORY_ID, scanner, ruleId, filePath ?? '', String(startLine)].join('|')).digest('hex');
  const packageInfo = scanner === 'SCA' ? (item.package ?? {}) : {};
  const affected = item.affected ?? [];
  const fixedVersions = affected.flatMap((entry) => (entry.ranges ?? []).flatMap((range) => (range.events ?? []).map((event) => event.fixed).filter(Boolean))).slice(0, 20);
  const rawSeverity = (Array.isArray(item.severity) ? undefined : item.severity) ?? item.level ?? item.database_specific?.severity ?? item.vulnerability?.severity;
  const cvssScore = Array.isArray(item.severity) ? Number(item.severity[0]?.score) : Number.NaN;
  const severity = String(rawSeverity ?? (Number.isFinite(cvssScore) ? cvssScore >= 9 ? 'CRITICAL' : cvssScore >= 7 ? 'HIGH' : cvssScore >= 4 ? 'MEDIUM' : 'LOW' : scanner === 'SCA' && fixedVersions.length ? 'HIGH' : 'UNKNOWN')).toUpperCase();
  const manifestPath = typeof item.manifestPath === 'string' ? item.manifestPath : undefined;
  return { scannerType: scanner, tool: scanner === 'SECRETS' ? 'gitleaks' : scanner === 'SCA' ? 'osv-scanner' : scanner === 'SAST' ? 'semgrep' : 'checkov', toolVersion, ruleId, title, description: title, severity: ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].includes(severity) ? severity : 'UNKNOWN', confidence: 'UNKNOWN', fingerprint, filePath, startLine: Number.isInteger(startLine) && startLine > 0 ? startLine : undefined, endLine: Number.isInteger(startLine) && startLine > 0 ? startLine : undefined, cweIds: [], cveIds: item.id ? [String(item.id)] : [], metadata: { scanner, packageName: packageInfo.name, currentVersion: packageInfo.version, ecosystem: packageInfo.ecosystem, manifestPath, fixedVersions, dependency: { packageName: packageInfo.name, currentVersion: packageInfo.version, fixedVersion: fixedVersions[0], manifestPath, packageManager: manifestPath?.includes('pnpm') ? 'pnpm' : 'npm' } } };
});

await rm(out, { recursive: true, force: true }); await mkdir(out, { recursive: true });
const results = [];
const runScanner = async (scannerType, scannerVersion, bin, args, output, timeout) => { try { return { scannerType, scannerVersion, result: await command(bin, args, output, timeout) }; } catch (error) { return { scannerType, scannerVersion, errorCode: String(error.code ?? 'SCANNER_EXECUTION_FAILED').slice(0, 500) }; } };
if (scanners.includes('secrets')) results.push(await runScanner('SECRETS', '8.24.2', 'gitleaks', ['detect', '--source', '.', '--report-format', 'json', '--report-path', join(out, 'gitleaks.json'), '--no-banner'], join(out, 'gitleaks.json'), 300_000));
if (scanners.includes('sca')) results.push(await runScanner('SCA', '2.0.2', 'osv-scanner', ['scan', 'source', '--format', 'json', '--output', join(out, 'osv.json'), '--recursive', '.'], join(out, 'osv.json'), 300_000));
if (scanners.includes('sast')) results.push(await runScanner('SAST', '1.91.0', 'semgrep', ['scan', '--config', 'p/security-audit', '--json', '--output', join(out, 'semgrep.json'), '.'], join(out, 'semgrep.json'), 600_000));
if (scanners.includes('iac')) results.push(await runScanner('IAC', '3.2.293', 'checkov', ['--directory', '.', '--output', 'json', '--output-file', join(out, 'checkov.json'), '--quiet'], join(out, 'checkov.json'), 300_000));
if (!allow) { console.log('Vulnera: resultados produzidos sem ingestão privilegiada (contexto não confiável).'); process.exit(0); }
if (!process.env.ACTIONS_ID_TOKEN_REQUEST_URL || !process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN) throw new Error('OIDC do GitHub não disponível; confira permissions.id-token: write');
const oidc = await fetch(`${process.env.ACTIONS_ID_TOKEN_REQUEST_URL}&audience=vulnera`, { headers: { Authorization: `bearer ${process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` } });
if (!oidc.ok) throw new Error(`Falha ao solicitar OIDC (${oidc.status})`);
const { value } = await oidc.json();
const exchange = await fetch(`${apiBase}/ingestion/oidc/exchange`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: value, repositoryId: process.env.VULNERA_REPOSITORY_ID, scanId: process.env.VULNERA_SCAN_ID, commitSha: process.env.VULNERA_COMMIT_SHA, ref: process.env.VULNERA_REF }) });
if (!exchange.ok) { const detail = await exchange.text().catch(() => ''); throw new Error(`Falha no exchange OIDC (${exchange.status}): ${detail.slice(0, 500)}`); }
const { token } = await exchange.json();
for (const item of results) {
  if (item.errorCode) {
    const failure = await fetch(`${apiBase}/ingestion/scanner-failure`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ scanId: process.env.VULNERA_SCAN_ID, manifestVersion: '1', commitSha: process.env.VULNERA_COMMIT_SHA, ref: process.env.VULNERA_REF, scannerType: item.scannerType, scannerVersion: item.scannerVersion, errorCode: item.errorCode }) });
    if (!failure.ok) throw new Error(`Falha ao registrar erro ${item.scannerType} (${failure.status})`);
    continue;
  }
  const body = { scanId: process.env.VULNERA_SCAN_ID, manifestVersion: '1', commitSha: process.env.VULNERA_COMMIT_SHA, ref: process.env.VULNERA_REF, scannerType: item.scannerType, scannerVersion: item.scannerVersion, findings: normalized(item.scannerType, item.scannerVersion, item.result), ...(item.scannerType === 'SCA' ? { dependencies: dependencies(item.result) } : {}) };
  const response = await fetch(`${apiBase}/ingestion/results`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (!response.ok) throw new Error(`Falha na ingestão ${item.scannerType} (${response.status})`);
  const accepted = await response.json();
  // Never persist Gitleaks output: raw reports may contain credential material.
  if (item.scannerType === 'SECRETS' || process.env.VULNERA_UPLOAD_ARTIFACTS !== 'true' || accepted.scannerExecutionId === undefined) continue;
  const raw = JSON.stringify(sanitize(item.result));
  const content = Buffer.from(raw).toString('base64');
  // Keep the complete JSON request below Fastify's 1 MiB body limit.
  // Base64 expands the report and the envelope adds additional bytes.
  if (Buffer.byteLength(content, 'utf8') > 700_000) { console.warn(`Vulnera: artefato ${item.scannerType} excede o limite e foi omitido.`); continue; }
  const artifact = await fetch(`${apiBase}/ingestion/artifacts`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ scanId: process.env.VULNERA_SCAN_ID, scannerExecutionId: accepted.scannerExecutionId, scannerType: item.scannerType, contentType: 'application/json', contentBase64: content }) });
  if (!artifact.ok) throw new Error(`Falha no upload do artefato ${item.scannerType} (${artifact.status})`);
}
