# AES-128-CBC-C#
aes-128-cbc encryption/decryption

AES 128 Encryption / Decryption

```
CSIdentityAPICrypto cS = new CSIdentityAPICrypto(" ### KEY ### ");
string encrypted = cS.AESEncrypt(" __YOUR__PLAIN__TEXT__");
Console.WriteLine(cS.AESDecrypt(encrypted));

string decrpted = cS.AESDecrypt(encrypted);
Console.WriteLine(cS.AESDecrypt(decrpted));
```
