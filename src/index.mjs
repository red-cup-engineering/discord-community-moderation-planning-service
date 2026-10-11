import { createHmac } from "node:crypto";
import { semanticHex } from "@red-cup-engineering/computer-content-address-engineering-services-section/semiotic-content-address";

const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const digestPattern = /^[a-f0-9]{64}$/u;
const actions = new Set(["warn", "timeout", "remove-role", "restore-role"]);
const timeoutMaximum = Object.freeze({ low: 3600, moderate: 86400, high: 604800 });
const safeguards = Object.freeze(["non-executable", "human-review-required", "fresh-state", "active-human-authority"]);

function plain(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`${label} must be a plain object`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError(`${label} must not have a custom prototype`);
  return value;
}
function keys(value, expected, label) {
  const actual = Object.keys(value);
  if (actual.length !== expected.length || expected.some((key) => !(key in value))) throw new TypeError(`${label} has unknown or missing fields`);
}
function id(value, label) {
  if (typeof value !== "string" || !identifierPattern.test(value)) throw new TypeError(`${label} must be an identifier`);
  return value;
}
function instant(value, label) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T.*Z$/u.test(value)) throw new TypeError(`${label} must be an ISO UTC timestamp`);
  const result = Date.parse(value);
  if (!Number.isFinite(result) || new Date(result).toISOString() !== value) throw new TypeError(`${label} must be an ISO UTC timestamp`);
  return result;
}
function position(value, label) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new TypeError(`${label} must be a finite non-negative integer`);
  return value;
}
function deepFreeze(value) {
  const copy = JSON.parse(JSON.stringify(value));
  const visit = (item) => { if (item !== null && typeof item === "object") { for (const child of Object.values(item)) visit(child); Object.freeze(item); } };
  visit(copy); return copy;
}
function action(value) {
  if (typeof value !== "string" || !actions.has(value)) throw new TypeError("action is unsupported");
  return value;
}

function normalizeCase(input) {
  const value = plain(input, "moderation case");
  keys(value, "appealOf" in value ? ["type", "version", "id", "guildId", "subjectId", "openedAt", "severity", "reasonCode", "evidenceDigest", "appealOf"] : ["type", "version", "id", "guildId", "subjectId", "openedAt", "severity", "reasonCode", "evidenceDigest"], "moderation case");
  if (value.type !== "DiscordModerationCase" || value.version !== 1) throw new TypeError("unsupported moderation case");
  if (value.severity !== "low" && value.severity !== "moderate" && value.severity !== "high") throw new TypeError("case severity is invalid");
  instant(value.openedAt, "case openedAt");
  if (typeof value.reasonCode !== "string" || value.reasonCode.length === 0 || value.reasonCode.length > 128) throw new TypeError("reason code is invalid");
  if (typeof value.evidenceDigest !== "string" || !digestPattern.test(value.evidenceDigest)) throw new TypeError("evidence digest is invalid");
  const caseId = id(value.id, "case id"), appealOf = "appealOf" in value ? id(value.appealOf, "appeal case id") : undefined;
  if (appealOf === caseId) throw new TypeError("appeal case may not link to itself");
  return deepFreeze({ id: caseId, guildId: id(value.guildId, "case guild id"), subjectId: id(value.subjectId, "case subject id"), openedAt: instant(value.openedAt, "case openedAt"), severity: value.severity, ...(appealOf === undefined ? {} : { appealOf }) });
}
function normalizeAuthority(input, now) {
  const value = plain(input, "human authority");
  keys(value, "revokedAt" in value ? ["type", "version", "guildId", "actorId", "grantedAt", "expiresAt", "revokedAt", "capabilities"] : ["type", "version", "guildId", "actorId", "grantedAt", "expiresAt", "capabilities"], "human authority");
  if (value.type !== "DiscordHumanModerationAuthority" || value.version !== 1) throw new TypeError("unsupported human authority");
  const granted = instant(value.grantedAt, "authority grantedAt"), expires = instant(value.expiresAt, "authority expiresAt"), revoked = "revokedAt" in value ? instant(value.revokedAt, "authority revokedAt") : undefined;
  if (granted > now || expires <= granted || expires <= now || (revoked !== undefined && revoked <= now)) throw new TypeError("human authority is inactive, expired, or revoked");
  if (!Array.isArray(value.capabilities) || value.capabilities.length === 0) throw new TypeError("authority capabilities are required");
  const capabilities = value.capabilities.map(action);
  if (new Set(capabilities).size !== capabilities.length) throw new TypeError("authority capabilities must be unique");
  return deepFreeze({ guildId: id(value.guildId, "authority guild id"), actorId: id(value.actorId, "authority actor id"), capabilities });
}
function normalizeState(input, now, maxAge) {
  const value = plain(input, "moderation state");
  const expected = ["type", "version", "guildId", "observedAt", "sourceRevision", "subjectProtected", "moderatorHighestRolePosition"];
  if ("targetRole" in value) expected.push("targetRole"); if ("appealDisposition" in value) expected.push("appealDisposition"); keys(value, expected, "moderation state");
  if (value.type !== "DiscordModerationState" || value.version !== 1) throw new TypeError("unsupported moderation state");
  if (!Number.isSafeInteger(maxAge) || maxAge <= 0) throw new TypeError("maxStateAgeMs must be a positive safe integer");
  const observed = instant(value.observedAt, "state observedAt"); if (observed > now) throw new TypeError("moderation state is from the future"); if (now - observed > maxAge) throw new TypeError("moderation state is stale");
  if (typeof value.subjectProtected !== "boolean") throw new TypeError("state subjectProtected must be boolean");
  let targetRole;
  if ("targetRole" in value) { const role = plain(value.targetRole, "target role"); keys(role, ["id", "managed", "position"], "target role"); if (typeof role.managed !== "boolean") throw new TypeError("target role managed must be boolean"); targetRole = deepFreeze({ id: id(role.id, "target role id"), managed: role.managed, position: position(role.position, "target role position") }); }
  if ("appealDisposition" in value && !["upheld", "denied", "pending"].includes(String(value.appealDisposition))) throw new TypeError("appeal disposition is invalid");
  return deepFreeze({ guildId: id(value.guildId, "state guild id"), observedAt: observed, sourceRevision: id(value.sourceRevision, "state source revision"), subjectProtected: value.subjectProtected, highest: position(value.moderatorHighestRolePosition, "moderator highest role position"), ...(targetRole === undefined ? {} : { targetRole }), ...("appealDisposition" in value ? { appealDisposition: value.appealDisposition } : {}) });
}
function normalizeArguments(input, selected, state, caseValue) {
  const value = plain(input, "action arguments");
  if (selected === "warn") { keys(value, [], "warn arguments"); return deepFreeze({}); }
  if (selected === "timeout") { keys(value, ["durationSeconds"], "timeout arguments"); if (typeof value.durationSeconds !== "number" || !Number.isSafeInteger(value.durationSeconds) || value.durationSeconds < 60 || value.durationSeconds > timeoutMaximum[caseValue.severity]) throw new TypeError("timeout duration is not proportional to case severity"); return deepFreeze({ durationSeconds: value.durationSeconds }); }
  keys(value, ["targetRoleId"], "role action arguments");
  if (state.targetRole === undefined || id(value.targetRoleId, "target role argument") !== state.targetRole.id) throw new TypeError("role action target must match the observed target role");
  if (state.targetRole.managed || state.targetRole.position >= state.highest) throw new TypeError("role action violates managed-role or hierarchy boundary");
  if (selected === "restore-role" && (caseValue.appealOf === undefined || state.appealDisposition !== "upheld")) throw new TypeError("role restoration requires an upheld appeal linkage");
  if (selected === "remove-role" && caseValue.appealOf !== undefined) throw new TypeError("appeal cases may not remove roles");
  return deepFreeze({ targetRoleId: state.targetRole.id });
}
function material(proposal) { return { authorityActorId: proposal.authorityActorId, caseId: proposal.caseId, guildId: proposal.guildId, action: proposal.action, subjectId: proposal.subjectId, arguments: proposal.arguments, reversible: proposal.reversible, ...(proposal.appealCaseId === undefined ? {} : { appealCaseId: proposal.appealCaseId }), expectedSourceRevision: proposal.expectedSourceRevision, safeguards: proposal.safeguards }; }

/** Pure planning only: the returned object requires separate human review and has no execution path. */
export function planModeration(input) {
  const value = plain(input, "moderation planning input");
  keys(value, ["case", "authority", "state", "action", "arguments", ...("now" in value ? ["now"] : []), ...("maxStateAgeMs" in value ? ["maxStateAgeMs"] : [])], "moderation planning input");
  const now = value.now === undefined ? new Date() : value.now; if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new TypeError("now must be a valid Date");
  const selected = action(value.action), caseValue = normalizeCase(value.case), authority = normalizeAuthority(value.authority, now.getTime()), state = normalizeState(value.state, now.getTime(), value.maxStateAgeMs === undefined ? 60000 : value.maxStateAgeMs);
  if (caseValue.openedAt > now.getTime() || caseValue.openedAt > state.observedAt) throw new TypeError("case openedAt must not follow the planning clock or state observation");
  if (caseValue.guildId !== authority.guildId || caseValue.guildId !== state.guildId) throw new TypeError("case, authority, and state must bind the same guild");
  if (!authority.capabilities.includes(selected)) throw new TypeError("authority capability is denied"); if (state.subjectProtected) throw new TypeError("protected subject requires human escalation outside this planner");
  const argumentsValue = normalizeArguments(value.arguments, selected, state, caseValue);
  const proposal = { type: "DiscordModerationReviewProposal", version: 1, executable: false, authority: "human-review-required", authorityActorId: authority.actorId, caseId: caseValue.id, guildId: caseValue.guildId, action: selected, subjectId: caseValue.subjectId, arguments: argumentsValue, reversible: selected !== "warn", ...(caseValue.appealOf === undefined ? {} : { appealCaseId: caseValue.appealOf }), expectedSourceRevision: state.sourceRevision, safeguards };
  return validateModerationProposal({ ...proposal, id: `discord-moderation-review:${semanticHex(material(proposal))}` });
}

/** Validates exact proposal shape and recomputes its structural digest before any adapter acts on it. */
export function validateModerationProposal(input) {
  const value = plain(input, "moderation proposal");
  keys(value, "appealCaseId" in value ? ["type", "version", "id", "executable", "authority", "authorityActorId", "caseId", "guildId", "action", "subjectId", "arguments", "reversible", "appealCaseId", "expectedSourceRevision", "safeguards"] : ["type", "version", "id", "executable", "authority", "authorityActorId", "caseId", "guildId", "action", "subjectId", "arguments", "reversible", "expectedSourceRevision", "safeguards"], "moderation proposal");
  if (value.type !== "DiscordModerationReviewProposal" || value.version !== 1 || value.executable !== false || value.authority !== "human-review-required") throw new TypeError("proposal must remain a non-executable human review");
  const selected = action(value.action); if (typeof value.reversible !== "boolean" || value.reversible !== (selected !== "warn")) throw new TypeError("proposal reversibility is invalid");
  if (!Array.isArray(value.safeguards) || value.safeguards.length !== safeguards.length || value.safeguards.some((item, index) => item !== safeguards[index])) throw new TypeError("proposal safeguards are invalid");
  const guildId = id(value.guildId, "proposal guild id"), actorId = id(value.authorityActorId, "proposal authority actor id"), caseId = id(value.caseId, "proposal case id"), subjectId = id(value.subjectId, "proposal subject id"), sourceRevision = id(value.expectedSourceRevision, "proposal source revision");
  const roleAction = selected === "remove-role" || selected === "restore-role";
  const roleId = roleAction ? id(plain(value.arguments, "proposal arguments").targetRoleId, "proposal target role id") : undefined;
  const pseudoState = { guildId, observedAt: 0, sourceRevision, subjectProtected: false, highest: 1, ...(roleId === undefined ? {} : { targetRole: { id: roleId, managed: false, position: 0 } }), ...(selected === "restore-role" ? { appealDisposition: "upheld" } : {}) };
  const pseudoCase = { id: caseId, guildId, subjectId, openedAt: 0, severity: "high", ...("appealCaseId" in value ? { appealOf: id(value.appealCaseId, "proposal appeal case id") } : {}) };
  const argumentsValue = normalizeArguments(value.arguments, selected, pseudoState, pseudoCase);
  if (selected === "restore-role" && !("appealCaseId" in value)) throw new TypeError("role restoration requires appeal linkage"); if (selected !== "restore-role" && "appealCaseId" in value) throw new TypeError("only restoration may contain appeal linkage");
  const proposal = { type: "DiscordModerationReviewProposal", version: 1, executable: false, authority: "human-review-required", authorityActorId: actorId, caseId, guildId, action: selected, subjectId, arguments: argumentsValue, reversible: selected !== "warn", ...("appealCaseId" in value ? { appealCaseId: pseudoCase.appealOf } : {}), expectedSourceRevision: sourceRevision, safeguards };
  const expected = `discord-moderation-review:${semanticHex(material(proposal))}`; if (value.id !== expected) throw new TypeError("proposal identity does not match its structure"); return deepFreeze({ ...proposal, id: expected });
}
function pseudonym(key, purpose, guildId, label, value) { return `urn:discord:moderation:${label}:${createHmac("sha256", key).update(`v1\0${purpose}\0${guildId}\0${label}\0${value}`).digest("hex")}`; }
/** Privacy projection omits every raw Discord identifier, reason, and evidence reference. */
export function projectModerationReceipt(input, options) {
  const proposal = validateModerationProposal(input), value = plain(options, "receipt options"); keys(value, ["pseudonymKey", "purpose"], "receipt options"); if (typeof value.pseudonymKey !== "string" || value.pseudonymKey.length < 32) throw new TypeError("pseudonym key must contain at least 32 characters"); const purpose = id(value.purpose, "receipt purpose");
  return deepFreeze({ type: "DiscordModerationReviewReceiptProjection", version: 1, purpose, action: proposal.action, reversible: proposal.reversible, proposalPseudonym: pseudonym(value.pseudonymKey, purpose, proposal.guildId, "proposal", proposal.id), casePseudonym: pseudonym(value.pseudonymKey, purpose, proposal.guildId, "case", proposal.caseId), subjectPseudonym: pseudonym(value.pseudonymKey, purpose, proposal.guildId, "subject", proposal.subjectId), authorityPseudonym: pseudonym(value.pseudonymKey, purpose, proposal.guildId, "authority", proposal.authorityActorId), privacy: { omitted: ["proposalId", "caseId", "guildId", "subjectId", "authorityActorId", "reasonCode", "evidenceDigest"] } });
}
