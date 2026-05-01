// 主密码强度评分（5.4）+ 解锁失败退避（5.5）
// 不依赖 zxcvbn 等大库；自实现简化评分

// ----- 5.4 强度评分 -----
// 返回 { score: 0..4, label, hints: [] }
export function scorePassword(pw) {
  const s = String(pw || "");
  const hints = [];
  let score = 0;

  if (s.length === 0) return { score: 0, label: "未输入", hints };

  // 长度
  if (s.length >= 16) score += 2;
  else if (s.length >= 12) score += 1;
  else if (s.length >= 8) score += 0;
  else { score -= 1; hints.push("至少 8 字符；推荐 12+"); }

  // 字符种类
  const hasLower = /[a-z]/.test(s);
  const hasUpper = /[A-Z]/.test(s);
  const hasDigit = /\d/.test(s);
  const hasSymbol = /[^A-Za-z0-9]/.test(s);
  const variety = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
  score += variety - 1;
  if (variety < 3) hints.push("混合大小写、数字与符号能显著提升强度");

  // 重复模式
  if (/^(.)\1+$/.test(s)) { score -= 2; hints.push("不要使用单一重复字符"); }
  if (/^[0-9]+$/.test(s)) { score -= 1; hints.push("纯数字易被破解"); }
  if (/(.)\1{2,}/.test(s)) hints.push("避免连续重复字符 (aaa)");
  if (/0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf/i.test(s)) {
    score -= 1; hints.push("避免顺序键盘 / 连续数字");
  }

  // 常见弱密码黑名单
  const weak = ["password", "123456", "12345678", "qwerty", "letmein", "admin", "iloveyou", "welcome", "abc123"];
  if (weak.some(w => s.toLowerCase().includes(w))) {
    score = Math.min(score, 0); hints.push("含常见弱口令字串");
  }

  score = Math.max(0, Math.min(4, score));
  const label = ["很弱", "较弱", "一般", "较强", "强"][score];
  return { score, label, hints };
}

// ----- 5.5 失败退避 -----
const SS_FAIL_COUNT = "authenticator.v1.unlockFails";
const SS_FAIL_UNTIL = "authenticator.v1.unlockBlockUntil";

export function getUnlockBlockMs() {
  const until = Number(sessionStorage.getItem(SS_FAIL_UNTIL) || 0);
  const left = until - Date.now();
  return left > 0 ? left : 0;
}

export function recordUnlockFail() {
  const n = Number(sessionStorage.getItem(SS_FAIL_COUNT) || 0) + 1;
  sessionStorage.setItem(SS_FAIL_COUNT, String(n));
  // 指数退避：第 3 次起开始限速
  if (n >= 3) {
    const delaySec = Math.min(60, 2 ** Math.min(6, n - 2)); // 2,4,8,16,32,60,60...
    const until = Date.now() + delaySec * 1000;
    sessionStorage.setItem(SS_FAIL_UNTIL, String(until));
    return delaySec;
  }
  return 0;
}

export function clearUnlockFails() {
  sessionStorage.removeItem(SS_FAIL_COUNT);
  sessionStorage.removeItem(SS_FAIL_UNTIL);
}
