import type { Confidence } from '../types/finding.js';
import type { Rule } from './rule.js';
import { makeFinding, scanUnits } from './helpers.js';

/**
 * Patterns that indicate an MCP server is attempting to gain elevated
 * privileges beyond what the current user has: running as root, reading
 * stdin passwords, escaping container namespaces, etc.
 */
const PATTERNS: ReadonlyArray<{ re: RegExp; label: string; confidence: Confidence }> = [
  // sudo with stdin password — common in headless privilege escalation
  { re: /\bsudo\s+(?:-[A-Za-z]*S[A-Za-z]*\s)/,            label: 'sudo -S (stdin password)', confidence: 'high' },
  // su (switch user)
  { re: /\bsu\s+(?:-\s+)?root\b|\bsu\s+-[lcms]*\s+root\b/, label: 'su root',                  confidence: 'high' },
  // Container/namespace escape tools
  { re: /\bnsenter\b/,                                       label: 'nsenter',                  confidence: 'high' },
  { re: /\bunshare\b/,                                       label: 'unshare',                  confidence: 'medium' },
  // Docker privilege modes
  { re: /\bdocker\b[^|;&\n]*--privileged\b/i,               label: 'docker --privileged',       confidence: 'high' },
  { re: /\bdocker\b[^|;&\n]*--cap-add\s+(?:ALL|SYS_ADMIN)\b/i, label: 'docker --cap-add SYS_ADMIN/ALL', confidence: 'high' },
  { re: /\bdocker\b[^|;&\n]*-v\s+\/:/i,                    label: 'docker -v / (root bind-mount)', confidence: 'high' },
  // setuid helpers
  { re: /\bchmod\s+(?:\+s|[0-7]*[46][0-7]{2})\b/,          label: 'setuid/setgid chmod',       confidence: 'high' },
  { re: /\binstall\s+[^|;&\n]*-m\s+(?:4|6)[0-7]{3}\b/i,   label: 'install -m (setuid)',        confidence: 'medium' },
  // Linux capabilities
  { re: /\bsetcap\b/,                                        label: 'setcap (capabilities)',     confidence: 'medium' },
  { re: /\bcap_net_admin|cap_sys_admin|cap_sys_ptrace|cap_sys_module/i, label: 'dangerous Linux capability', confidence: 'medium' },
  // Process injection / ptrace
  { re: /\bptrace\b/i,                                       label: 'ptrace',                   confidence: 'medium' },
  { re: /\bgdb\b[^|;&\n]*--pid\b/i,                         label: 'gdb --pid (process attach)',confidence: 'medium' },
  // Kernel module loading
  { re: /\binsmod\b|\bmodprobe\b/,                           label: 'kernel module load',        confidence: 'high' },
];

export const AG015: Rule = {
  id: 'AG-015',
  nameEn: 'Privilege Escalation Pattern',
  nameJa: '特権昇格パターン',
  severity: 'critical',
  explanationEn:
    'The MCP server configuration contains commands or patterns associated with privilege escalation: gaining root access, escaping container sandboxes, loading kernel modules, or injecting into running processes. ' +
    'An MCP server should never need elevated privileges; their presence is a strong indicator of malicious intent.',
  explanationJa:
    'MCPサーバーの設定に特権昇格を示すコマンドやパターン（root権限の取得、コンテナサンドボックスの脱出、カーネルモジュールの読み込み、プロセスへの注入など）が含まれています。' +
    'MCPサーバーが管理者権限を必要とすることは通常ありません。このような記述は悪意の強いシグナルです。',
  recommendationEn:
    'Do not connect this server. Legitimate MCP servers run as ordinary users. Remove any privilege-escalation commands and check with the provider if this is intentional.',
  recommendationJa:
    'このサーバーには接続しないでください。正当なMCPサーバーは通常ユーザー権限で動作します。特権昇格コマンドをすべて削除し、意図的なものである場合は提供元に確認してください。',
  check(target) {
    if (target.kind === 'env-file') return [];
    const findings = [];

    for (const unit of scanUnits(target)) {
      for (const p of PATTERNS) {
        if (p.re.test(unit.value)) {
          findings.push(
            makeFinding(AG015, {
              target,
              confidence: p.confidence,
              path: unit.path,
              evidence: unit.value,
              detailEn: p.label,
              detailJa: p.label,
            }),
          );
          break; // one finding per unit
        }
      }
    }

    return findings;
  },
};
