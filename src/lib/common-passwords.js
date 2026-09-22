'use strict';

/**
 * A blocklist of passwords that appear near the top of every public breach
 * corpus, plus their trivial variants. Compared against both the raw
 * lower-cased password and a letters-and-digits-only normalisation, so
 * "P@ssw0rd!" and "Passw0rd" are both caught.
 *
 * This is deliberately small and offline. For a larger deployment, check
 * candidates against the Have I Been Pwned range API (k-anonymity) as well —
 * see README, "Hardening beyond the defaults".
 */
const LIST = [
  '123456', '123456789', '12345678', '12345', '1234567', '1234567890', '1234',
  '111111', '000000', '121212', '123123', '654321', '666666', '888888', '987654321',
  'password', 'password1', 'password123', 'passw0rd', 'pass', 'passwd', 'p@ssword',
  'qwerty', 'qwerty123', 'qwertyuiop', 'qwe123', '1q2w3e4r', '1qaz2wsx', 'zaq12wsx',
  'asdfgh', 'asdfghjkl', 'zxcvbnm', 'azerty', 'iloveyou', 'admin', 'administrator',
  'admin123', 'root', 'toor', 'guest', 'user', 'test', 'test123', 'demo', 'default',
  'letmein', 'welcome', 'welcome1', 'welcome123', 'monkey', 'dragon', 'sunshine',
  'princess', 'football', 'baseball', 'basketball', 'superman', 'batman', 'trustno1',
  'master', 'shadow', 'michael', 'jennifer', 'jordan', 'hunter', 'freedom', 'whatever',
  'starwars', 'charlie', 'donald', 'login', 'access', 'secret', 'changeme',
  'abc123', 'abcd1234', 'a1b2c3d4', 'qazwsx', 'ninja', 'cheese', 'computer',
  'internet', 'samsung', 'google', 'facebook', 'linkedin', 'twitter', 'summer',
  'winter', 'spring', 'autumn', 'january', 'february', 'december', 'chocolate',
  'flower', 'hello', 'hello123', 'love', 'lovely', 'family', 'naruto', 'pokemon',
  'minecraft', 'soccer', 'liverpool', 'arsenal', 'chelsea', 'barcelona', 'realmadrid',
  'matrix', 'mustang', 'harley', 'ranger', 'buster', 'thomas', 'robert', 'daniel',
  'andrew', 'joshua', 'matthew', 'nicole', 'ashley', 'amanda', 'jessica', 'hannah',
  'tigger', 'purple', 'orange', 'yellow', 'silver', 'golden', 'diamond', 'phoenix',
  'qwertyui', 'asdf1234', 'zxcvbn', 'poiuytrewq', 'lkjhgfdsa', 'mnbvcxz',
  'passwordpassword', 'letmein123', 'iloveyou1', 'sunshine1', 'princess1',
  'correcthorsebatterystaple', 'thisisapassword', 'mypassword', 'newpassword',
  'temppassword', 'temporary', 'secret123', 'secure', 'security', 'trustme',
  'server', 'database', 'oracle', 'postgres', 'mysql', 'sqlserver', 'redis',
  'docker', 'kubernetes', 'jenkins', 'developer', 'webmaster', 'support',
  'service', 'manager', 'operator', 'supervisor', 'company', 'business',
  'apple', 'microsoft', 'windows', 'linux', 'ubuntu', 'android', 'iphone',
  'qwerty1234', 'password1234', 'admin1234', 'welcome1234', '1234abcd',
];

const COMMON_PASSWORDS = new Set(LIST);

// Add letters-and-digits-only forms so punctuation substitutions do not help.
for (const entry of LIST) {
  COMMON_PASSWORDS.add(entry.replace(/[^a-z0-9]/g, ''));
}

module.exports = { COMMON_PASSWORDS };
