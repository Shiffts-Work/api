export function IsMatch(
  roles: string | string[],
  userGroups: string[],
): boolean {
  if (typeof roles === 'string') roles = [roles];

  return roles.some((role) => userGroups.includes(role));
}
