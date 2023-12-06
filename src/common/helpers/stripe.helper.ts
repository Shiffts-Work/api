export class StripeHelper {
  public static convertCentsToEuro(price: number): number {
    if (!price) return 0;
    return price / 100;
  }

  public static convertEuroToCents(price: number) {
    return price * 100;
  }
}
