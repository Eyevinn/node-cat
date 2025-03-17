import { CommonAccessTokenUri, CommonAccessTokenUriMap } from './catu';

function compareMaps(
  mapA: CommonAccessTokenUriMap,
  mapB: CommonAccessTokenUriMap
): boolean {
  if (mapA.size !== mapB.size) {
    return false;
  }

  for (const [key, valueA] of mapA.entries()) {
    const valueB = mapB.get(key);
    if (!valueB) {
      return false;
    }
    if (valueA.size !== valueB.size) {
      return false;
    }
    for (const [innerKey, innerValueA] of valueA.entries()) {
      const innerValueB = valueB.get(innerKey);
      if (!innerValueB || innerValueA !== innerValueB) {
        return false;
      }
    }
  }
  return true;
}

describe('Common Access Token Uri', () => {
  test('can be constructed from a dict', async () => {
    const exact = CommonAccessTokenUri.fromDict({
      scheme: {
        'exact-match': 'https'
      }
    });
    expect(exact).toBeDefined();
    expect(exact.payload.get(0)?.get(0)).toEqual('https');

    const multi = CommonAccessTokenUri.fromDict({
      scheme: {
        'exact-match': 'https'
      },
      path: {
        'prefix-match': '/api'
      },
      extension: {
        'exact-match': '.m3u8'
      }
    });
    expect(multi).toBeDefined();
    expect(multi.payload.get(0)?.get(0)).toEqual('https');
    expect(multi.payload.get(3)?.get(1)).toEqual('/api');
    expect(multi.payload.get(8)?.get(0)).toEqual('.m3u8');
  });

  test('can be constructed from another map', async () => {
    const fromDict = CommonAccessTokenUri.fromDict({
      scheme: {
        'exact-match': 'https'
      },
      path: {
        'prefix-match': '/api'
      },
      extension: {
        'exact-match': '.m3u8'
      }
    });
    const fromMap = CommonAccessTokenUri.fromMap(fromDict.payload);
    expect(compareMaps(fromDict.payload, fromMap.payload)).toBeTruthy();
  });

  test('can match a URI with a scheme exactly equal to "https"', async () => {
    const catu = CommonAccessTokenUri.fromDict({
      scheme: {
        'exact-match': 'https'
      }
    });
    const uri = new URL('https://example.com/api/v1');
    expect(await catu.match(uri)).toBeTruthy();
  });

  test('can match a URI with scheme exactly equal to "https" and path prefixed with "/api"', async () => {
    const catu = CommonAccessTokenUri.fromDict({
      scheme: {
        'exact-match': 'https'
      },
      path: {
        'prefix-match': '/api'
      }
    });
    const uri = new URL('https://example.com/api/v1');
    expect(await catu.match(uri)).toBeTruthy();
  });

  test('can match a URI with scheme "https", path starts with "/content" and extension is exactly ".m3u8"', async () => {
    const catu = CommonAccessTokenUri.fromDict({
      scheme: {
        'exact-match': 'https'
      },
      path: {
        'prefix-match': '/content'
      },
      extension: {
        'exact-match': '.m3u8'
      }
    });
    const uri = new URL('https://example.com/content/path/file.m3u8');
    expect(await catu.match(uri)).toBeTruthy();
    const nomatch = new URL('https://example.com/CONTENT/path/file.m3u8');
    expect(await catu.match(nomatch)).toBeFalsy();
  });

  test('can match a URI that have a filename that end in ".tar.gz"', async () => {
    const catu = CommonAccessTokenUri.fromDict({
      filename: {
        'suffix-match': '.tar.gz'
      }
    });
    const uri = new URL('https://example.com/file.txt.tar.gz');
    expect(await catu.match(uri)).toBeTruthy();
  });

  test('can match a URI that have no extension', async () => {
    const catu = CommonAccessTokenUri.fromDict({
      extension: {
        'exact-match': ''
      }
    });
    const uri = new URL('https://example.com/file');
    expect(await catu.match(uri)).toBeTruthy();
  });

  test('can match a URI have a full stop at the end of the filename', async () => {
    const catu = CommonAccessTokenUri.fromDict({
      extension: {
        'exact-match': '.'
      }
    });
    const uri = new URL('https://example.com/file.');
    expect(await catu.match(uri)).toBeTruthy();
  });

  test('can match URIs that end in "content" in the penultimate segment', async () => {
    const catu = CommonAccessTokenUri.fromDict({
      'parent-path': {
        'suffix-match': 'content'
      }
    });
    const uri = new URL('https://example.com/files/secret-content/secret.txt');
    expect(await catu.match(uri)).toBeTruthy();
  });

  test('can match URIs that end in "/content" in the penultimate segment', async () => {
    const catu = CommonAccessTokenUri.fromDict({
      'parent-path': {
        'suffix-match': '/content'
      }
    });
    const nomatch = new URL(
      'https://example.com/files/secret-content/secret.txt'
    );
    expect(await catu.match(nomatch)).toBeFalsy();
    const uri = new URL('https://example.com/files/content/file.txt');
    expect(await catu.match(uri)).toBeTruthy();
  });

  test('can match URIs that have aparent path that match the specified hash', async () => {
    const catu256 = CommonAccessTokenUri.fromDict({
      'parent-path': {
        'sha256-match':
          '14608dd0f26a05afce0b80443c6d3643bc84771469748314808d64381b99898c'
      }
    });
    const catu512 = CommonAccessTokenUri.fromDict({
      'parent-path': {
        'sha512-256-match':
          '006c29d231e2ffc4cc9e0db0536219dba7a6b470eee816a6e779354aae9a62f1f1e35b8d47131e4a9d4eeaf6a3bdb0e6ecc8c4db47af6ea1bf2765d3f9a2ba4f'
      }
    });
    const uri = new URL(
      'https://example.com/highly/nested/file/structure/that/extends/on/and/takes/quite/a/bit/of/space/and/might/consume/more/space/in/the/token/than/is/otherwise/preferable/file.txt'
    );
    expect(await catu256.match(uri)).toBeTruthy();
    expect(await catu512.match(uri)).toBeTruthy();
  });

  test('can match URIs for port 8080', async () => {
    const catu = CommonAccessTokenUri.fromDict({
      port: {
        'exact-match': '8080'
      }
    });
    const uri = new URL('https://example.com:8080/content.ts');
    const uri2 = new URL('http://example.com:8080/content.ts');
    const nomatch = new URL('http://example.com/content.ts');
    expect(await catu.match(uri)).toBeTruthy();
    expect(await catu.match(uri2)).toBeTruthy();
    expect(await catu.match(nomatch)).toBeFalsy();
  });

  test('can match normalized port match for default ports', async () => {
    const catu = CommonAccessTokenUri.fromDict({
      port: {
        'exact-match': ''
      }
    });
    const uri1 = new URL('http://example.com');
    const uri2 = new URL('http://example.com:80');
    const uri3 = new URL('https://example.com');
    expect(await catu.match(uri1)).toBeTruthy();
    expect(await catu.match(uri2)).toBeTruthy();
    expect(await catu.match(uri3)).toBeTruthy();
  });

  test('can match URI filenames', async () => {
    const catu = CommonAccessTokenUri.fromDict({
      filename: {
        'exact-match': 'content.tar.gz'
      }
    });
    const uri = new URL('https://example.com/content.tar.gz');
    const uri2 = new URL(
      'https://example.com/content.tar.gz?foo=query&bar=yes'
    );
    expect(await catu.match(uri)).toBeTruthy();
    expect(await catu.match(uri2)).toBeTruthy();
  });

  test('can match stems', async () => {
    const catu = CommonAccessTokenUri.fromDict({
      stem: {
        'exact-match': 'content'
      }
    });
    const uri = new URL('https://example.com/a/content');
    const uri2 = new URL(
      'https://example.com/path/to/content.tar.gz?foo=query&bar=yes'
    );
    expect(await catu.match(uri)).toBeTruthy();
    expect(await catu.match(uri2)).toBeTruthy();
  });
});
