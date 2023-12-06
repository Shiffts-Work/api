export function getKeyByValue<T extends { [index: string]: string }>(
  enumType: T,
  enumValue: string,
): keyof T | undefined {
  const key = Object.keys(enumType).find((key) => enumType[key] === enumValue);
  return key as keyof T | undefined;
}
