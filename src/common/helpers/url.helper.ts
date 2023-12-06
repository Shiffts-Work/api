export const extractParamsFromURL = (url: URL): Record<string, any> => {
  return JSON.parse(
    '{"' +
      decodeURI(url.search.substring(1))
        .replace(/"/g, '\\"')
        .replace(/&/g, '","')
        .replace(/=/g, '":"') +
      '"}',
  );
};
