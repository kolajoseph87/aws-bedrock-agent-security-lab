"""Deterministic, side-effect-free Chapter 9 event and detection teaching code."""
import datetime as dt
import hashlib, hmac, json, re
ALLOWED={"event_id","schema_version","timestamp","sequence_number","previous_event_hash","event_hash",
         "correlation_id","principal_id","session_id_hash","tenant_id_hash","repository_id_hash",
         "model_id","policy_version","stage","action","decision","reason_code","latency_ms",
         "input_tokens","output_tokens"}
REQUIRED=ALLOWED
SECRET=re.compile(r"(?i)(bearer\s+[a-z0-9._-]+|aws[_-]?secret|password\s*[=:]|patient|ssn|@)")
STAGES={"PRE_INPUT","MODEL","POST_RETRIEVAL","PRE_TOOL","WORKER","PRE_OUTPUT","RELEASE","DEPLOY"}
def deny(reason): return {"allow":False,"reason":reason,"side_effects":0}
def keyed_hash(value,key):
 if not isinstance(key,bytes) or len(key)<32: raise ValueError("A secret key of at least 32 bytes is required")
 return hmac.new(key,(value or "").encode(),hashlib.sha256).hexdigest()
def event_hash(event,key):
 body={k:event[k] for k in sorted(event) if k!="event_hash"}
 return hmac.new(key,json.dumps(body,separators=(",",":"),sort_keys=True).encode(),hashlib.sha256).hexdigest()
def _timestamp(value):
 try: return dt.datetime.fromisoformat(value.replace("Z","+00:00"))
 except (AttributeError,ValueError): return None
def sanitize_event(event,server_principal,server_tenant_hash,server_repository_hash,integrity_key):
 if set(event)!=ALLOWED: return deny("SCHEMA_DENIED")
 if any(event.get(k) in (None,"") for k in REQUIRED): return deny("REQUIRED_FIELD_MISSING")
 if event["principal_id"]!=server_principal: return deny("PRINCIPAL_MISMATCH")
 if event["tenant_id_hash"]!=server_tenant_hash or event["repository_id_hash"]!=server_repository_hash:
  return deny("SCOPE_MISMATCH")
 if event["decision"] not in {"ALLOW","DENY","ERROR"}: return deny("DECISION_DENIED")
 if event["schema_version"]!="1" or event["stage"] not in STAGES: return deny("EVENT_ENUM_DENIED")
 if _timestamp(event["timestamp"]) is None: return deny("TIMESTAMP_INVALID")
 if not isinstance(event["sequence_number"],int) or event["sequence_number"]<1: return deny("SEQUENCE_INVALID")
 if any(not isinstance(event[k],int) or event[k]<0 for k in ["latency_ms","input_tokens","output_tokens"]):
  return deny("METRIC_INVALID")
 if any(SECRET.search(str(v)) for v in event.values()): return deny("SENSITIVE_VALUE_DENIED")
 if any(not re.fullmatch(r"[0-9a-f]{64}",event[k] or "") for k in ["session_id_hash","tenant_id_hash","repository_id_hash","previous_event_hash","event_hash"]): return deny("HASH_INVALID")
 if not hmac.compare_digest(event["event_hash"],event_hash(event,integrity_key)):
  return deny("EVENT_INTEGRITY_INVALID")
 return {"allow":True,"reason":"EVENT_SANITIZED","event":dict(event),"side_effects":0}
def deliver_event(sanitized,telemetry_available=True,agent_disable_requested=False,buffer_size=0,max_buffer=100):
 if agent_disable_requested: return deny("TELEMETRY_DISABLE_DENIED")
 if not sanitized.get("allow"): return deny("UNSANITIZED_EVENT")
 if telemetry_available: return {"allow":True,"reason":"AUDIT_DELIVERED","side_effects":0}
 if buffer_size>=max_buffer: return deny("AUDIT_DELIVERY_FAILED")
 return {"allow":False,"reason":"AUDIT_BUFFERED_ACTION_BLOCKED","buffered":True,"side_effects":0}
def detect(events,expected_policy="policy-v9",expected_model="approved-model",denial_threshold=3,
           latency_threshold_ms=5000,token_threshold=10000,clock_skew_seconds=300):
 alerts=[]; seen=set(); denials=0; previous_sequence=0; previous_hash="0"*64; previous_time=None
 reason_alerts={
  "PROMPT_INJECTION":"PROMPT_INJECTION",
  "CROSS_TENANT":"CROSS_TENANT",
  "CROSS_REPOSITORY":"CROSS_REPOSITORY",
  "TOOL_AUTHORIZATION_FAILED":"TOOL_AUTHORIZATION_FAILED",
  "WORK_ORDER_REPLAY":"WORK_ORDER_REPLAY",
  "UNEXPECTED_TOOL":"UNEXPECTED_TOOL_OR_RESOURCE",
  "UNEXPECTED_RESOURCE":"UNEXPECTED_TOOL_OR_RESOURCE",
  "CREDENTIAL_DETECTED":"CREDENTIAL_DETECTED",
  "PHI_DETECTED":"PHI_DETECTED",
  "RELEASE_BYPASS":"RELEASE_BYPASS",
  "DEPLOYMENT_BYPASS":"DEPLOYMENT_BYPASS",
  "TELEMETRY_DISABLED":"TELEMETRY_GAP_OR_TAMPER",
 }
 for e in events:
  event_id=e.get("event_id")
  if event_id in seen: alerts.append("DUPLICATE_EVENT_REPLAY")
  seen.add(event_id)
  sequence=e.get("sequence_number")
  if sequence!=previous_sequence+1: alerts.append("TELEMETRY_SEQUENCE_GAP")
  if e.get("previous_event_hash")!=previous_hash: alerts.append("TELEMETRY_GAP_OR_TAMPER")
  previous_sequence=sequence if isinstance(sequence,int) else previous_sequence
  previous_hash=e.get("event_hash","")
  stamp=_timestamp(e.get("timestamp"))
  if stamp is None: alerts.append("CLOCK_SYNCHRONIZATION_FAILURE")
  elif previous_time and abs((stamp-previous_time).total_seconds())>clock_skew_seconds:
   alerts.append("CLOCK_SYNCHRONIZATION_FAILURE")
  if stamp: previous_time=stamp
  if e.get("decision")=="DENY": denials+=1
  if e.get("reason_code") in reason_alerts: alerts.append(reason_alerts[e["reason_code"]])
  if e.get("policy_version")!=expected_policy: alerts.append("POLICY_VERSION_DRIFT")
  if e.get("model_id")!=expected_model: alerts.append("MODEL_VERSION_DRIFT")
  if e.get("latency_ms",0)>latency_threshold_ms or e.get("input_tokens",0)+e.get("output_tokens",0)>token_threshold:
   alerts.append("TOKEN_COST_OR_LATENCY_ANOMALY")
 if denials>=denial_threshold: alerts.append("RUNTIME_DENIAL_SPIKE")
 return sorted(set(alerts))
