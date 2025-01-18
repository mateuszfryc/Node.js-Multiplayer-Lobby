import {
  EMAIL_REGEX,
  PASSWORD_REGEX,
  PLAYER_NAME_REGEX,
} from '#config/consts.js';
import net from 'net';

export function validatePort(port) {
  const parsed = parseInt(port, 10);
  return Number.isInteger(parsed) && parsed > 0 && parsed <= 65535;
}

export function validateIpOrLocalhost(ip) {
  if (ip === 'localhost') return true;
  return net.isIP(ip) !== 0;
}

export function validateEmailFormat(email) {
  return EMAIL_REGEX.test(email);
}

export function validatePasswordFormat(pw) {
  return PASSWORD_REGEX.test(pw);
}

export function validatePlayerNameFormat(n) {
  return PLAYER_NAME_REGEX.test(n);
}
