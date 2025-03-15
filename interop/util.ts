export const testIf = (condition: boolean, ...args: Parameters<typeof test>) =>
  condition ? test(...args) : test.skip(...args);
