export function Log(obj: any, opts?: any) {
  if (process.env.DEBUG) {
    if (opts) {
      console.dir(obj, opts);
    } else {
      console.log(obj);
    }
  }
}
