export const USER_CHARS = /^[A-Za-z0-9!@#$%^&*\+\-\?, ]+$/;
export const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export const PASSWORD_REGEX =
  /^(?=.*[0-9])(?=.*[A-Z])(?=.*[a-z])(?=.*[!@#$%^&*\+\-\?,])[A-Za-z0-9!@#$%^&*\+\-\?,]{8,}$/;
export const PLAYER_NAME_REGEX = /^[A-Za-z0-9!@#$%^&*\+\-\?,]{3,16}$/;
