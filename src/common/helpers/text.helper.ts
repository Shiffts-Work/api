export class TextHelper {
  static prettify(text?: string | null): string {
    text ||= '';

    return TextHelper.capitalizeFirstLetter(text.replace(/_/g, ' '));
  }

  static capitalizeFirstLetter(text?: string | null): string {
    text ||= '';

    return text.charAt(0).toUpperCase() + text.slice(1).toLowerCase();
  }

  static formatPossessive(text?: string | null): string {
    text ||= '';

    return text.endsWith('s') ? `${text}'` : `${text}'s`;
  }

  static formatWithGBPCurrency(value: number | string): null | string {
    const { format: formatWithGBPCurrency } = Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'GBP',
    });

    if (typeof value === 'string') {
      value = parseFloat(value);
    }

    return formatWithGBPCurrency(value);
  }

  static removeSpecialCharactersUnicode(input: string): string {
    // Normalize Unicode string to decompose combined characters
    const normalized = input.normalize('NFD');

    // This regex matches anything that is not an English letter, number, period, or space
    const regex = /[^A-Za-z0-9. ]/g;

    // Replace characters that match the regex with an empty string
    return normalized.replace(regex, '');
  }
}
