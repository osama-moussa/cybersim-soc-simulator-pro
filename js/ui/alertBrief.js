// js/ui/alertBrief.js — "Brief" box inside the alert detail view.
// Explains WHAT the rule detects, WHY it matters, and WHAT to check.
// Rule-level text only: it never reads alert.truth and never states a verdict.
// Public API: AlertBrief.get(alert), AlertBrief.mount(detailEl, alert)

(() => {
  if (!document.getElementById('ab-style')) {
    const style = document.createElement('style');
    style.id = 'ab-style';
    style.textContent = `
      .ab-box { margin: 1rem 0; padding: .9rem 1rem; border: 1px solid var(--border, #475569);
                border-left: 4px solid var(--accent, #06b6d4); border-radius: 8px; background: rgba(15, 23, 42, .5); }
      .ab-h { margin: 0 0 .6rem; font-size: .85rem; letter-spacing: .04em; text-transform: uppercase;
              color: var(--accent, #06b6d4); }
      .ab-box h5 { margin: .7rem 0 .25rem; font-size: .78rem; color: var(--text-muted, #94a3b8);
                   text-transform: uppercase; letter-spacing: .04em; }
      .ab-box p { margin: 0; font-size: .9rem; line-height: 1.55; }
      .ab-box ul { margin: 0; padding-left: 1.2rem; font-size: .9rem; line-height: 1.6; }
    `;
    document.head.appendChild(style);
  }

  const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // ---------------------------------------------------------------- rule library
  const BRIEFS = {
    'AD: Kerberoasting (multiple TGS requests, RC4)': {
      what: 'One account requested many Kerberos service tickets (TGS) in a short time, using weak RC4 encryption.',
      why: 'Attackers request service tickets for service accounts, then crack them offline to recover passwords. Some old applications and scanners also generate bursts of TGS requests.',
      check: ['Which account and host sent the requests, and is that normal for them?', 'Which service accounts (SPNs) were requested, and how many?', 'Was a vulnerability scanner or an inventory tool running at that time?', 'Any later logon with those service accounts?'],
    },
    'AD: directory replication from non-DC (DCSync)': {
      what: 'A machine that is not a Domain Controller asked AD to replicate directory data (event 4662 / replication rights).',
      why: 'Real DCs replicate with each other all the time. A normal workstation or server doing it can mean someone is pulling password hashes out of AD.',
      check: ['Is the source IP/host a known Domain Controller or an approved Azure AD Connect server?', 'Which account performed the replication and does it normally have that right?', 'Any change ticket or admin task that explains it?'],
    },
    'AV: malware detected': {
      what: 'The endpoint protection engine matched a file to a known malware signature.',
      why: 'Check whether the product already blocked/quarantined it. A blocked file is a different situation than a file that ran.',
      check: ['What was action_taken (quarantined, blocked, allowed)?', 'Look the file hash up with IOC lookup.', 'How did the file arrive (email, download, USB)? Search logs on this host around the same time.', 'Did the same hash appear on other hosts?'],
    },
    'DLP: large outbound transfer': {
      what: 'A host sent an unusually large amount of data out of the network.',
      why: 'Large uploads can be data theft, but also backups, software updates, or cloud sync that nobody told the SOC about.',
      check: ['Who owns the source host, and is that role expected to upload data?', 'Look up the destination domain/IP with IOC lookup.', 'Compare bytes_out with what is normal for this host.', 'Check the change calendar and notices for backups or migrations.'],
    },
    'DLP: large outbound transfer to file-sharing site': {
      what: 'A host uploaded a large amount of data to a public file-sharing or cloud storage service.',
      why: 'Personal file-sharing can move company data outside of its control. Approved business cloud services use the same kind of traffic.',
      check: ['Is the destination service approved by the company?', 'Who is the user and what is their role?', 'How much data and over what time?', 'Is there a recent notice about resignation, project handover, or approved migration?'],
    },
    'DLP: mass download from document repository': {
      what: 'One user downloaded a very large number of files from a document repository in a short time.',
      why: 'It can mean data collection before leaving the company, or a sync client, backup or migration doing a normal bulk read.',
      check: ['How many files, and from which folders/sites?', 'Does the user\'s job need that data?', 'Was it a sync tool or a scheduled job?', 'Any follow-up upload, USB copy, or email to external addresses?'],
    },
    'DNS: high query volume': {
      what: 'A host made far more DNS queries than usual.',
      why: 'High volume can be a misconfigured application, a monitoring tool, or DNS used to move data or reach a control server.',
      check: ['Are the queried names random-looking or repeated for one domain?', 'Look up the domain with IOC lookup.', 'Which process or tool runs on that host?', 'Is this host a known monitoring or scanning server?'],
    },
    'DNS: periodic beaconing to rare domain': {
      what: 'A host contacts the same rare domain at a fixed interval (for example every 60 seconds).',
      why: 'Regular, machine-like timing to a rare domain is how some malware checks in with its operator. Some legitimate agents and apps also poll on a timer.',
      check: ['Look up the domain: reputation, age, category.', 'Which process on the host makes the queries?', 'How long has it been happening, and does the interval stay almost identical?', 'Do other hosts query the same domain?'],
    },
    'EDR: Encoded PowerShell command': {
      what: 'PowerShell ran with a Base64-encoded command line (-enc / -EncodedCommand).',
      why: 'Encoding hides what the command does, which attackers like. Some admin and deployment scripts use it too.',
      check: ['Decode the command and read what it does.', 'What is the parent process (Office, a script host, a management agent)?', 'Does the command download anything or contact an external domain?', 'Is the user an admin who normally runs scripts?'],
    },
    'EDR: LSASS memory access': {
      what: 'A process opened the memory of LSASS, the Windows process that holds logon credentials.',
      why: 'Credential-dumping tools do exactly this. Security products and some backup agents also touch LSASS.',
      check: ['Which process accessed LSASS and where does it run from?', 'Is it a known security or backup tool?', 'What command line and parent process started it?', 'Any logons from this account to other hosts afterwards?'],
    },
    'EDR: Office spawned command interpreter': {
      what: 'An Office program (Word, Excel...) started cmd, PowerShell or a similar interpreter.',
      why: 'Normal documents rarely do this. Malicious macros do. A few internal macros or add-ins can also launch scripts.',
      check: ['Which document opened it and where did it come from (email, download)?', 'What command line did the interpreter get?', 'Was the action blocked (action_taken)?', 'Look up the file hash and any URL/domain in the command.'],
    },
    'EDR: PowerShell download cradle': {
      what: 'PowerShell was used to download content from a URL and run it.',
      why: 'This is a common way to fetch a second-stage payload. Some installers and admin scripts also download files with PowerShell.',
      check: ['Look up the domain in the command with IOC lookup.', 'What is the parent process?', 'Was the downloaded content saved or executed?', 'Is this host a server or an admin workstation that runs such scripts?'],
    },
    'EDR: Remote service created (PsExec)': {
      what: 'A service was created remotely on a host, the way PsExec and similar tools work.',
      why: 'Attackers use it to move between machines. IT teams use PsExec-style tools for remote administration as well.',
      check: ['Which source host and account created the service?', 'Is the source an admin/jump host?', 'Is there a ticket or change record for it?', 'What did the service run (command_line)?'],
    },
    'EDR: USB mass storage connected': {
      what: 'A USB storage device was plugged into a host.',
      why: 'USB can bring in malware or carry data out. It is also a very normal thing for users to do.',
      check: ['Which user and which host? Is USB allowed for this role?', 'Were files copied to the device (look for related alerts)?', 'Any other alerts on the same host around this time?'],
    },
    'EDR: archive utility staging large dataset': {
      what: 'An archive tool (7z, zip, rar) packed a large amount of data on a host.',
      why: 'Attackers often compress data before sending it out. Users and backup jobs also create archives.',
      check: ['What was archived and how big is the archive?', 'Who ran it and what is their job?', 'Any upload, USB copy, or large outbound transfer afterwards?', 'What was the parent process?'],
    },
    'EDR: autorun executable blocked': {
      what: 'The endpoint blocked an executable that tried to start automatically, typically from removable media.',
      why: 'Autorun malware spreads through USB drives. A blocked file means the product stopped it, but you still need to know where it came from.',
      check: ['Look up the file hash.', 'Which drive or path did it start from?', 'Were other files from the same device executed on this host or others?'],
    },
    'EDR: bulk copy to USB storage': {
      what: 'Many files were copied from a host to a USB storage device.',
      why: 'It can be data theft, or someone moving their own files or a presentation.',
      check: ['What kind of files and how many?', 'Does the user\'s role need this data?', 'Any notice about the user leaving or a project that explains it?', 'Related alerts on the same user or host.'],
    },
    'EDR: potentially unwanted program installed': {
      what: 'Software classified as a potentially unwanted program (PUP) was installed, for example adware or a bundled toolbar.',
      why: 'PUPs are usually low risk but can open the door to worse software or be a sign of poor download habits.',
      check: ['What is the file and does the hash look known?', 'What was action_taken?', 'How was it installed (user download, bundled with other software)?'],
    },
    'EDR: shadow copies deleted': {
      what: 'Volume Shadow Copies (Windows backups) were deleted on a host.',
      why: 'Ransomware deletes them so files can\'t be restored. Backup and disk-cleanup tools can also remove old copies.',
      check: ['Which process and command line did it (vssadmin, wmic, PowerShell)?', 'Any mass file rename or encryption alerts on the same host?', 'Is it a scheduled maintenance task?', 'Which user ran it?'],
    },
    'Email: bulk sender flagged as phishing': {
      what: 'The mail gateway marked a bulk or marketing-style email as possible phishing.',
      why: 'Newsletters and marketing emails look similar to phishing (tracking links, many recipients). Authentication results help tell them apart.',
      check: ['Read spf, dkim and dmarc: do they pass and do they match the sender domain?', 'Look at the sender domain with IOC lookup.', 'Was it quarantined? Did the user click anything?', 'Does the content ask for credentials or payment?'],
    },
    'Email: inbox rule forwarding to external address': {
      what: 'A mailbox rule was created that forwards the user\'s mail to an outside address.',
      why: 'Attackers who get into a mailbox add forwarding to keep reading mail. Users sometimes forward work mail to a personal account.',
      check: ['Which external address is it and is it known?', 'Who created the rule and from which IP?', 'Was there a sign-in from a new location before the rule was created?', 'Search the logs for the user around the same time.'],
    },
    'Email: macro-enabled attachment': {
      what: 'An email carried a macro-enabled Office document.',
      why: 'Macros are a common malware delivery method, and also used by finance and operations teams with internal files.',
      check: ['Look up the file hash.', 'Who is the sender and does SPF/DKIM/DMARC pass?', 'Was it delivered or quarantined (action_taken)?', 'Did the recipient open it? Check EDR/proxy logs on that host.'],
    },
    'Email: outbound payment-change request': {
      what: 'An email asks to change bank or payment details for a supplier or payment.',
      why: 'Business Email Compromise (BEC) fraud works this way, from a hijacked mailbox or a look-alike sender. Real suppliers also change banks.',
      check: ['Does the sender address and source IP match what you normally see for this person?', 'Is the request unusual in tone, urgency, or recipient?', 'Is there any record of a legitimate change request?', 'Notify the right team before any payment is changed.'],
    },
    'Email: suspicious link detected': {
      what: 'An email contains a link that the gateway considers suspicious.',
      why: 'Phishing emails lead to fake login pages or malware downloads. Some legitimate services use redirect or tracking links that look odd.',
      check: ['Look up the URL domain with IOC lookup.', 'Check the sender and SPF/DKIM/DMARC.', 'Was the mail delivered? Did the user click (proxy logs)?', 'Did other users receive the same mail?'],
    },
    'File integrity: new .aspx file in web root': {
      what: 'File integrity monitoring saw a new .aspx file appear in a web server\'s web root.',
      why: 'Attackers drop web shells this way. Developers deploying a new page create the same event.',
      check: ['Does a deployment or change ticket explain the file?', 'Which process created it?', 'Check web server logs for requests to that file.', 'Is the file name random or unusual for this application?'],
    },
    'File server: mass file rename / entropy spike': {
      what: 'Many files on a file server were renamed or rewritten, with content that looks random (high entropy).',
      why: 'That is the pattern of ransomware encrypting files. Bulk renames from an approved tool are possible but less likely.',
      check: ['Which source IP/account is doing it, and how fast is it spreading?', 'Do the new file names have a strange extension or a ransom note appeared?', 'Any shadow copy deletion or PsExec alerts nearby?', 'This is time-sensitive: treat it urgently.'],
    },
    'Firewall: external port scan': {
      what: 'An outside IP probed many ports on company systems.',
      why: 'Internet-facing systems get scanned all day, so most are noise. A scan followed by other activity from the same IP is more interesting.',
      check: ['Look up the source IP with IOC lookup.', 'Was the traffic blocked (action_taken)?', 'Did the same IP appear in other alerts (web, VPN, SSH)?'],
    },
    'Firewall: outbound reverse shell from web server': {
      what: 'A web server opened an outbound connection to an external host on an unusual port.',
      why: 'Web servers normally receive connections rather than start them. An outbound connection like this is how reverse shells work.',
      check: ['Look up the destination IP and port.', 'Does that server legitimately call external services?', 'Any new file, WAF, or process alerts on the same server?', 'Was the connection blocked or allowed?'],
    },
    'IDS: Port scan detected': {
      what: 'The network IDS saw one host probing many ports or hosts.',
      why: 'Inside the network, scans come from vulnerability scanners and IT tools, but also from an attacker mapping the network.',
      check: ['Is the source an approved scanner (check the change calendar and notices)?', 'Internal or external source IP?', 'Anything on the targeted hosts afterward (logons, new connections)?'],
    },
    'Identity: password spray pattern': {
      what: 'One IP tried a few common passwords against many accounts.',
      why: 'Spraying avoids account lockouts by trying few passwords per account. Misconfigured apps and shared NAT addresses can also create many failures.',
      check: ['How many accounts and how many failures, from how many IPs?', 'Look up the source IP and geo.', 'Was there any successful sign-in from the same IP?', 'Are the targeted accounts alphabetical or from a list?'],
    },
    'Identity: sign-in from new IP / location': {
      what: 'An account signed in from an IP or place it has not used before.',
      why: 'It can be a stolen password, but also travel, a new phone, or a home network.',
      check: ['Read mfa_result: was MFA required and passed?', 'Look up the IP and geo; is it a VPN or hosting provider?', 'Does the user have a travel notice?', 'Any suspicious activity after the sign-in?'],
    },
    'Linux: new user + cron persistence': {
      what: 'A new user was created on a Linux host and a cron job was added.',
      why: 'Attackers create accounts and scheduled jobs to keep access. Admins also add users and cron jobs during setup.',
      check: ['Who ran the commands and from where?', 'What does the cron job run?', 'Is there a change ticket?', 'Any SSH logins just before this?'],
    },
    'Multiple failed logons': {
      what: 'Many failed logons happened on an account or host in a short time.',
      why: 'It can be brute force, but also a user with a wrong password, an expired service password, or a stuck mapped drive.',
      check: ['Which account, which source IP, and what logon_type?', 'Is the source internal or external?', 'Did a successful logon (4624) follow the failures?', 'Is it a service or scheduled task account?'],
    },
    'Network: Tor relay connection': {
      what: 'A host connected to an IP that is a known Tor relay.',
      why: 'Tor hides who is connecting. It can be a user\'s curiosity or an attacker hiding command-and-control traffic.',
      check: ['Which host/user and which process?', 'Was it blocked?', 'Is Tor allowed for any role (security research)?', 'Other alerts on the same host?'],
    },
    'Network: connection to cryptomining pool': {
      what: 'A host connected to a known cryptocurrency mining pool.',
      why: 'Miners are installed without permission to steal computing power, or by someone on the inside.',
      check: ['Which host and process?', 'Is CPU usage high on that host?', 'Look up the pool domain/IP.', 'How long has it been running?'],
    },
    'Proxy: credentials submitted to uncategorized domain': {
      what: 'A user submitted a login form to a domain the proxy has no category for.',
      why: 'Fake login pages collect passwords. Some new but legitimate vendors are also uncategorized.',
      check: ['Look up the domain: age, reputation, resemblance to a company or known brand.', 'What was the URL and how did the user get there?', 'Was the request blocked?', 'If credentials were sent to a fake page, the account needs attention.'],
    },
    'Proxy: executable from uncategorized domain': {
      what: 'A user downloaded an executable file from a domain the proxy has no category for.',
      why: 'Malware often comes from new or unknown sites. Some software vendors use fresh domains too.',
      check: ['Look up the domain and file hash.', 'Was the download blocked or allowed?', 'Did the file run on the host (EDR)?', 'What page or email led the user there?'],
    },
    'Proxy: request blocked (phishing category)': {
      what: 'The web proxy blocked a request because the site is categorized as phishing.',
      why: 'The control worked, but the user may still have clicked a malicious link and may have received the mail.',
      check: ['Which user and what URL?', 'Did the user reach any other related site?', 'How did they get the link (email)? Search for the same URL across other users.'],
    },
    'Proxy: suspicious executable download': {
      what: 'The proxy saw an executable downloaded in a way that looks suspicious.',
      why: 'The file could be malware, or an installer from a vendor.',
      check: ['Look up the file hash and URL domain.', 'Was it blocked (action_taken)?', 'Did the file execute?', 'Is it software the user needs for their job?'],
    },
    'SMB: admin share access from workstation': {
      what: 'A workstation accessed an administrative share (like C$ or ADMIN$) on another machine.',
      why: 'Attackers use admin shares to copy files and move between machines. IT staff use them too.',
      check: ['Which account and source host? Is it an admin workstation?', 'Which target host?', 'Is there a ticket or planned work?', 'Anything executed on the target afterward?'],
    },
    'SSH: brute force attempts': {
      what: 'Many failed SSH logins came from one IP.',
      why: 'Internet-facing SSH servers get this constantly. It matters when it succeeds or when it comes from inside.',
      check: ['Look up the source IP.', 'Is the SSH server exposed to the internet?', 'Is there any successful login from the same IP?'],
    },
    'SSH: successful login after brute force': {
      what: 'A successful SSH login came from an IP that earlier failed many times.',
      why: 'It means the guessing may have worked, or the user simply typed the password wrong several times first.',
      check: ['Same source IP for failures and the success?', 'Which account, and is that IP normal for them?', 'What did the session do after login (new users, cron, downloads)?'],
    },
    'Server: sustained high CPU': {
      what: 'A server has been running at high CPU for a long time.',
      why: 'It can be a busy workload, a runaway process, or hidden mining software.',
      check: ['Which process uses the CPU, and is it expected on this server?', 'Any alert for connections to a mining pool?', 'Is there a scheduled job or deployment?'],
    },
    'VPN: login from new country': {
      what: 'A VPN login came from a country this user does not usually use.',
      why: 'It could be a stolen account. Business travel and mobile networks produce the same alert.',
      check: ['Read mfa_result and look up the IP/geo.', 'Check notices and the change calendar for travel.', 'Is the user already signed in from their usual location at the same time?', 'What did the account do after connecting?'],
    },
    'WAF: SQL injection attempts': {
      what: 'The web application firewall saw requests that look like SQL injection.',
      why: 'Public sites receive these from automated scanners all the time. It matters when requests get through or the application shows errors.',
      check: ['Was the request blocked (action_taken)?', 'Look up the source IP; how many requests?', 'Did the application return errors or large responses?', 'Is the IP a known security scanner?'],
    },
  };

  const BY_SOURCE = {
    'Email Gateway': 'Check the sender, SPF/DKIM/DMARC results, links or attachments, and whether the user interacted.',
    'EDR': 'Check the process, its parent process, the command line, and what else ran on this host.',
    'Firewall': 'Check source and destination, the port, whether it was blocked, and look up external IPs.',
    'Web Proxy': 'Check the URL, the domain reputation, whether it was blocked, and what the user did next.',
  };

  function get(alert) {
    const b = BRIEFS[alert?.rule];
    if (b) return b;
    return {
      what: `This rule fired from ${alert?.source || 'a security source'}: ${alert?.summary || 'see the details below'}.`,
      why: 'Not enough information in the rule name alone. Judge it from the evidence.',
      check: [BY_SOURCE[alert?.source] || 'Check the entities in the details (host, user, IPs, domains) with the Toolkit, and search the logs around the alert time.'],
    };
  }

  function mount(detailEl, alert) {
    if (!detailEl || !alert) return;
    detailEl.querySelectorAll('[data-ab]').forEach(n => n.remove());
    const b = get(alert);
    const root = document.createElement('section');
    root.className = 'ab-box';
    root.setAttribute('data-ab', '');
    root.innerHTML = `
      <h4 class="ab-h">Brief</h4>
      <h5>What happened</h5><p>${esc(b.what)}</p>
      <h5>Why it matters</h5><p>${esc(b.why)}</p>
      <h5>What to check</h5><ul>${b.check.map(c => `<li>${esc(c)}</li>`).join('')}</ul>`;
    const anchor = detailEl.querySelector('.aq-summary');
    if (anchor) anchor.after(root); else detailEl.append(root);
  }

  window.AlertBrief = { get, mount, BRIEFS };
})();
