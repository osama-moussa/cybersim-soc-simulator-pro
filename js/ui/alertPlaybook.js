// js/ui/alertPlaybook.js — "Playbook" box inside the alert detail, based on SOC Tier 1 Alert-Handling Playbook v1.1.
// Maps every alert rule (by its exact name) to one of the 13 playbooks and shows:
// investigation steps, response/containment, escalation, plus the shared framework (A1-A4).
// Rule-level guidance only: it never reads alert.truth and never states a verdict.
// Self-installing: wraps AlertQueueUI.prototype.openDetail (no edits to alertQueue.js).

(() => {
  const Q = window.AlertQueueUI;
  if (!Q || !Q.prototype || typeof Q.prototype.openDetail !== 'function') {
    console.warn('[alertPlaybook] AlertQueueUI.openDetail not found; playbook box skipped.');
    return;
  }

  if (!document.getElementById('apb-style')) {
    const style = document.createElement('style');
    style.id = 'apb-style';
    style.textContent = `
      .apb-box { margin: 1rem 0; padding: .9rem 1rem; border: 1px solid var(--border, #475569);
                 border-left: 4px solid var(--primary, #3b82f6); border-radius: 8px; background: rgba(15, 23, 42, .5); }
      .apb-h { margin: 0 0 .5rem; font-size: .85rem; letter-spacing: .04em; text-transform: uppercase; color: var(--accent, #06b6d4); }
      .apb-box h5 { margin: .7rem 0 .25rem; font-size: .78rem; color: var(--text-muted, #94a3b8); text-transform: uppercase; letter-spacing: .04em; }
      .apb-box ul { margin: 0; padding-left: 1.2rem; font-size: .88rem; line-height: 1.55; }
      .apb-box p { margin: 0; font-size: .88rem; line-height: 1.55; }
      .apb-box details { margin-top: .6rem; }
      .apb-box summary { cursor: pointer; font-size: .82rem; color: var(--accent, #06b6d4); }
    `;
    document.head.appendChild(style);
  }

  const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // ---------------------------------------------------------------- playbooks (from the PDF)
  const PB = {
    1: { title: 'Suspicious Email (Phishing / Malicious Email)',
      steps: ['Inspect headers: From vs Return-Path/Reply-To, look-alike domains, SPF/DKIM/DMARC results.',
        'Extract URLs and attachment hashes; check them in URLScan / VirusTotal / sandbox. Never open attachments on your own workstation.',
        'User behavior: did the user reach the link (proxy logs)? Was the attachment executed or were credentials submitted (POST)?',
        'Scope: search the gateway and mailboxes for the same sender, subject, URL or hash to find all recipients and clickers.',
        'If credentials were submitted: look for new inbox rules and suspicious sign-ins after the click.'],
      resp: ['False Positive: close and document the reason.',
        'Link clicked only (no credentials, no download): P3, warn the user and monitor.',
        'True Positive (credentials submitted or attachment executed, P2): isolate the user host; reset password, revoke sessions, re-register MFA; block sender/IP/domain/hash and purge the message from all mailboxes; remove malicious inbox rules; notify affected users.'] },
    2: { title: 'Brute Force and Unauthorized Login Attempts',
      steps: ['Follow Event IDs 4625 (failed), 4624 (success; check Logon Type 3/10), 4740 (lockout), 4771/4776; on Linux /var/log/auth.log or /var/log/secure.',
        'Identify the pattern: brute force (many passwords, one account), password spraying (few passwords, many accounts), credential stuffing. Is the source internal or external?',
        'Check the source IP reputation (AbuseIPDB, OTX).',
        'Compromise check: a 4624 right after 4625 from the same source, successes from the same IP on other accounts, MFA status, new device or unusual location.'],
      resp: ['No success (P3): block the source IP on WAF/Firewall, notify IAM, consider temporary lockout or conditional access.',
        'Successful guess (P2, P1 if privileged): disable the account, revoke sessions, reset credentials, escalate to Tier 2 for post-exploitation review.'] },
    3: { title: 'Malware and Suspicious Process Execution',
      steps: ['Process lineage: parent/child (for example cmd/powershell launched from excel/winword).',
        'Command lines via Sysmon 1 / Event 4688; decode encoded PowerShell (-enc, Base64).',
        'File path, digital signature and hash (VirusTotal); suspicious paths like AppData\\Local\\Temp or C:\\Windows\\Tasks.',
        'Persistence: Run keys (Sysmon 13), scheduled tasks (4698), new services (7045/4697), WMI subscriptions (Sysmon 19-21), Startup folder.',
        'Related activity: outbound connections (Sysmon 3), dropped files (Sysmon 11), lsass.exe access (Sysmon 10).',
        'Scope: hunt in EDR for the same hash or command line on other hosts.'],
      resp: ['Isolate the affected host through SIEM/EDR.',
        'Kill the malicious process; remove related files and registry keys; run a full scan; collect a sample for forensics.',
        'If the same IOCs appear on other hosts, or credentials were accessed: escalate to Tier 2 / IR and reset passwords of users logged on to the host.'] },
    4: { title: 'Command-and-Control (C2) and Suspicious DNS',
      steps: ['DNS analysis: long high-entropy subdomains, high query volume, heavy TXT queries, newly registered domains.',
        'Beaconing: regular communications at fixed intervals to external IPs.',
        'Link the connection to a process: Sysmon 3 / 22 or EDR to find the Process ID.',
        'Destination reputation in threat intel and domain age (WHOIS).',
        'Scope: other hosts querying the same domain or contacting the same IP.'],
      resp: ['Isolate the endpoint and block its internet access.',
        'Add the domain and external IP to Firewall blocklists and the DNS sinkhole.',
        'Take a memory dump and escalate to IR Team / Tier 2 (P1 / P2).'] },
    5: { title: 'Privilege Escalation and Suspicious Administrative Activity',
      steps: ['Review Event IDs 4720 (new account), 4728/4732/4756 (group membership, e.g. Domain Admins), 4672 (special privileges), 4724 (password reset by another account).',
        'Match the action against ITSM/Jira change tickets from the same time frame.',
        'Confirm who performed it, from which source host, and when (off-hours?).',
        'Check the executing admin account for recent suspicious logons and other changes; check the first logon of any new account.'],
      resp: ['Disable the new account and revoke unauthorized privileges.',
        'Freeze the responsible admin account until verified: needs SOC Lead / IR approval (A3); under active abuse use the emergency exception.',
        'Escalate urgently to the IR Team (P1 / P2) and notify IAM.'] },
    6: { title: 'Data Exfiltration and Suspicious Outbound Traffic',
      steps: ['Look for abnormal outbound volume from a specific device.',
        'Inspect destination and protocol: SFTP/FTP, unapproved cloud services, personal email, auto-forwarding, DNS/ICMP tunneling.',
        'Match transferred files against DLP rules (cards, passports, source code).',
        'Context: archive staging before the transfer (zip/7z/rar; Sysmon 1 and 11), off-hours activity, user role, approved business request?'],
      resp: ['Cut the device network connection to stop the transfer.',
        'Block unauthorized cloud storage on Firewall/Proxy.',
        'Preserve evidence (proxy logs, DLP events, file list) and report urgently to Compliance and Legal via IR; P1 once sensitive data is confirmed.'] },
    7: { title: 'Ransomware Activity',
      steps: ['File-system signs: mass renames/modifications, new extensions, ransom notes in many folders (Sysmon 11, EDR).',
        'Recovery inhibition: vssadmin/wmic/wbadmin deletion, bcdedit changes.',
        'Defense evasion: security tools stopped (Defender 5001/5010), event logs cleared (Security 1102, System 104).',
        'Spread and origin: patient zero, responsible process and parent, encrypted network shares, other affected hosts.'],
      resp: ['Isolate the host immediately via EDR (emergency exception, A3). Do not shut down or reboot, to preserve memory.',
        'Disable the affected user account and any account used by the process; isolate other hosts with the same activity or share access.',
        'Declare P1 and escalate immediately to IR Team and SOC Manager. Do not contact the attackers or discuss payment.',
        'Preserve evidence (ransom note, sample, logs); do not delete encrypted files.'] },
    8: { title: 'Lateral Movement',
      steps: ['Unusual logons: 4624 Type 3 or 10 from workstations that do not normally connect to the target; 4648; RDP events 4778/4779/1149.',
        'Remote execution tools: PsExec (PSEXESVC, 7045), remote WMI (wmiprvse spawning cmd/powershell), remote scheduled tasks (4698), admin shares (5140/5145: ADMIN$, C$).',
        'Credential abuse: pass-the-hash (unexpected NTLM, 4776), Kerberoasting (many 4769 with RC4 0x17), lsass access (Sysmon 10).',
        'Build the chain: source host, account used, every host reached. Is a privileged account involved?'],
      resp: ['Isolate the source host and targeted hosts (servers need approval per A3, unless the emergency exception applies).',
        'Disable abused accounts, revoke sessions, reset credentials; privileged accounts follow A3.',
        'Escalate to the IR Team as P1 / P2. Tier 1 does not attempt full eradication.'] },
    9: { title: 'Web Application Attacks (SQLi / XSS / Path Traversal)',
      steps: ['Inspect WAF and web server logs for attack patterns in URI or body (\' OR 1=1, UNION SELECT, ../, <script>, ${jndi:).',
        'Success assessment: blocked 403 vs 200/500, response size anomalies, new files requested by the same source later.',
        'Source and tooling: IP reputation, scanner user agents (sqlmap, nikto, nuclei); mass scan or targeted?',
        'Post-exploitation on the server: new web root files (web shells), web server process spawning cmd/sh, unexpected outbound connections.'],
      resp: ['Blocked or failed attempts (P4 / P3): block the source IP on the WAF and document.',
        'Possible success (P2 / P1): escalate to Tier 2 / IR, notify the application owner, apply a virtual patch or WAF rule, isolate the server after approval (A3).'] },
    10: { title: 'Cloud Identity Attacks and Business Email Compromise (BEC)',
      steps: ['Suspicious sign-ins: impossible travel, anonymizers/TOR, legacy authentication, unfamiliar devices (IdP sign-in logs).',
        'MFA abuse: many push denials then an approval (fatigue), or a new MFA method registered right after a risky sign-in.',
        'Mailbox changes: new inbox rules (forward externally, delete, move), new delegates, forwarding.',
        'App consent and BEC signs: new OAuth consents, external emails requesting payment or bank-detail changes from the mailbox, look-alike domains.'],
      resp: ['Revoke all sessions and tokens, reset the password, re-register MFA.',
        'Remove malicious inbox rules, forwarding and OAuth consents; block the malicious IP or named location.',
        'BEC: alert Finance immediately to hold or recall any payment; escalate to IR (P1 if money was transferred or the account is privileged).'] },
    11: { title: 'Insider Threat and Removable Media (USB)',
      steps: ['Device activity: new external storage (Event 6416, EDR/device control) and large copies to removable media.',
        'Behavior and access: data unrelated to the role, bulk downloads or printing, off-hours activity, personal cloud storage or email.',
        'HR context (resignation, disciplinary) can only be obtained through IR / HR. Match with DLP alerts and approved exceptions.'],
      resp: ['Handle confidentially: do not confront or alert the user; share details only with IR, HR and Legal.',
        'Preserve evidence (device logs, DLP events, file lists) and escalate to IR; restrict access or block the device only on their authorization.'] },
    12: { title: 'Vulnerability Exploitation Attempts',
      steps: ['Validate the alert: CVE and signature behind the IDS/IPS or EDR alert, and the target asset.',
        'Exposure check: asset inventory, patch status, internet-facing?, listed in CISA KEV?',
        'Success indicators: unexpected child processes from the vulnerable service, new web shells or accounts, new outbound connections, crashes then restarts.'],
      resp: ['Target patched or attack blocked (P4 / P3): document and block the source IP.',
        'Vulnerable and exposed, or signs of success (P2 / P1): isolate the host after approval (A3), apply an IPS rule or virtual patch, request emergency patching, escalate to IR.'] },
  };

  // rule name -> playbook number (exact rule strings used by the scenarios)
  const MAP = {
    1: ['Email: bulk sender flagged as phishing', 'Email: macro-enabled attachment', 'Email: suspicious link detected',
        'Proxy: credentials submitted to uncategorized domain', 'Proxy: request blocked (phishing category)'],
    2: ['Multiple failed logons', 'Identity: password spray pattern', 'SSH: brute force attempts', 'SSH: successful login after brute force'],
    3: ['AV: malware detected', 'EDR: Encoded PowerShell command', 'EDR: Office spawned command interpreter', 'EDR: PowerShell download cradle',
        'EDR: LSASS memory access', 'EDR: autorun executable blocked', 'EDR: potentially unwanted program installed',
        'Proxy: executable from uncategorized domain', 'Proxy: suspicious executable download', 'Server: sustained high CPU',
        'Linux: new user + cron persistence'],
    4: ['DNS: high query volume', 'DNS: periodic beaconing to rare domain', 'Network: Tor relay connection',
        'Network: connection to cryptomining pool', 'Firewall: outbound reverse shell from web server'],
    6: ['DLP: large outbound transfer', 'DLP: large outbound transfer to file-sharing site', 'DLP: mass download from document repository',
        'EDR: archive utility staging large dataset'],
    7: ['EDR: shadow copies deleted', 'File server: mass file rename / entropy spike'],
    8: ['AD: Kerberoasting (multiple TGS requests, RC4)', 'AD: directory replication from non-DC (DCSync)',
        'EDR: Remote service created (PsExec)', 'SMB: admin share access from workstation'],
    9: ['WAF: SQL injection attempts', 'File integrity: new .aspx file in web root'],
    10: ['Email: outbound payment-change request', 'Email: inbox rule forwarding to external address',
         'Identity: sign-in from new IP / location', 'VPN: login from new country'],
    11: ['EDR: USB mass storage connected', 'EDR: bulk copy to USB storage'],
    12: ['Firewall: external port scan', 'IDS: Port scan detected'],
  };
  const NOTE = {
    'Firewall: external port scan': 'The playbook has no dedicated scan playbook; use the closest one (vulnerability exploitation attempts) and look for follow-up activity from the same source.',
    'IDS: Port scan detected': 'The playbook has no dedicated scan playbook; use the closest one (vulnerability exploitation attempts) and look for follow-up activity from the same source.',
    'Network: connection to cryptomining pool': 'Closest playbook is C2 / suspicious network traffic; also check the host for unauthorized mining software.',
    'Server: sustained high CPU': 'Closest playbook is malware / suspicious process; identify the process using the CPU first.',
    'AD: directory replication from non-DC (DCSync)': 'Also see Playbook 5 (privileged activity): involvement of privileged accounts means the IR Team immediately.',
    'Firewall: outbound reverse shell from web server': 'Also see Playbook 9 (post-exploitation on a web server). A server needs approval before isolation (A3).',
  };
  const RULE2PB = {};
  Object.entries(MAP).forEach(([n, rules]) => rules.forEach(r => { RULE2PB[r] = Number(n); }));

  const ESCALATION = 'Escalate to Tier 2 within the severity SLA (max 1 hour) when a True Positive shows confirmed account or host compromise. ' +
    'Escalate to the IR Team immediately when a privileged, admin or service account is involved, or on signs of ransomware, lateral movement or sensitive data exfiltration. ' +
    'If you cannot reach a verdict within the triage SLA, escalate to Tier 2.';

  const FRAMEWORK = `
    <details><summary>Severity and SLA (A1)</summary>
      <ul><li>P1 Critical: acknowledge 15 min, triage 30 min, escalate immediately, updates every 30 min.</li>
      <li>P2 High: 30 min / 1 hour, escalate within 1 hour, updates every 2 hours.</li>
      <li>P3 Medium: 2 hours / 8 hours, escalate if True Positive, daily updates.</li>
      <li>P4 Low: 1 business day / 2 business days, escalation not required.</li>
      <li>Raise severity by one level when the asset is critical (domain controllers, production servers, executive accounts, regulated data).</li></ul></details>
    <details><summary>Containment authority (A3)</summary>
      <ul><li>Pre-approved for Tier 1: isolate a standard user workstation via EDR; reset password and revoke sessions of a standard user; block malicious external IPs/domains (not business-critical); purge malicious emails; disable a confirmed-compromised standard account.</li>
      <li>Needs SOC Lead / asset owner approval: isolating servers, production systems or domain controllers; disabling admin, service or executive accounts; blocking internal ranges or business-critical domains; shutting down services.</li>
      <li>Emergency exception: if destructive activity or privileged abuse is actively spreading (e.g. ransomware encrypting), isolate or disable immediately, then notify the SOC Manager and IR within 15 minutes and document the justification.</li></ul></details>
    <details><summary>Evidence and ticket fields (A4)</summary>
      <ul><li>Collect volatile evidence first (processes, connections, logged-on users); isolation preserves memory; do not reboot an affected host unless IR says so.</li>
      <li>Ticket: alert ID, detection time, analyst, severity; affected users/hosts/IPs; IOCs; timeline of events and actions; verdict with justification; scope; containment actions and approvals; escalation; evidence; recommendations.</li></ul></details>`;

  function mount(detail, alert) {
    detail.querySelectorAll('[data-apb]').forEach(n => n.remove());
    const n = RULE2PB[alert.rule];
    const pb = n && PB[n];
    if (!pb) return;
    const root = document.createElement('section');
    root.className = 'apb-box';
    root.setAttribute('data-apb', '');
    root.innerHTML = `
      <h4 class="apb-h">Playbook ${n}: ${esc(pb.title)}</h4>
      ${NOTE[alert.rule] ? `<p><em>${esc(NOTE[alert.rule])}</em></p>` : ''}
      <h5>Investigation steps</h5><ul>${pb.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ul>
      <h5>Response and containment</h5><ul>${pb.resp.map(s => `<li>${esc(s)}</li>`).join('')}</ul>
      <h5>Escalation</h5><p>${esc(ESCALATION)}</p>
      ${FRAMEWORK}`;
    const anchor = detail.querySelector('.ab-box') || detail.querySelector('.aq-summary');
    if (anchor) anchor.after(root); else detail.append(root);
  }

  const orig = Q.prototype.openDetail;
  Q.prototype.openDetail = function (id, ...rest) {
    const r = orig.call(this, id, ...rest);
    try {
      const detail = document.getElementById('aq-detail');
      const alert = (window.shiftState?.alerts || []).find(a => a.id === id);
      if (detail && alert) mount(detail, alert);
    } catch (e) { console.warn('[alertPlaybook] mount failed:', e); }
    return r;
  };

  window.AlertPlaybook = { RULE2PB, PB };
})();
