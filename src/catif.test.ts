import { CommonAccessTokenIf } from './catif';

describe('Common Access Token If', () => {
  test('can be constructed from a dict', async () => {
    const basic = CommonAccessTokenIf.fromDict({
      exp: [
        307,
        {
          Location: 'https://auth.example.net/'
        }
      ]
    });
    expect(basic.toDict()).toEqual({
      exp: [307, { Location: 'https://auth.example.net/' }]
    });

    const advanced = CommonAccessTokenIf.fromDict({
      exp: [
        307,
        {
          Location: [
            'https://auth.example.net/?CAT=',
            {
              iss: null,
              iat: null
            }
          ]
        },
        'mykey'
      ]
    });
    expect(advanced.toDict()).toEqual({
      exp: [
        307,
        {
          Location: [
            'https://auth.example.net/?CAT=',
            {
              iss: null,
              iat: null
            }
          ]
        },
        'mykey'
      ]
    });
  });
});
