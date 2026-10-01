// Harness linking Armory's real EncryptionUtils.cpp to produce reference vectors.
#include "EncryptionUtils.h"
#include <cstdio>

static SecureBinaryData H(const char* h) { return SecureBinaryData(BinaryData::CreateFromHex(h)); }
static SecureBinaryData S(const char* s) { return SecureBinaryData(std::string(s)); }

int main()
{
   // KDF vectors
   struct { const char* pw; uint32_t mem; uint32_t it; const char* salt; } kv[] = {
      {"abcde", 1024, 1, "0000000000000000000000000000000000000000000000000000000000000000"},
      {"abcde", 1024, 3, "0000000000000000000000000000000000000000000000000000000000000000"},
      {"This is my first password", 65536, 2, "1ee82e6ef29655e597da9954b64aab87b470126c7b28b76d3d41168946305ffe"},
      {"abcde", 2097152, 2, "1ee82e6ef29655e597da9954b64aab87b470126c7b28b76d3d41168946305ffe"},
      {"abcde", 1024, 0, "0000000000000000000000000000000000000000000000000000000000000000"},
   };
   for (auto& k : kv) {
      KdfRomix kdf(k.mem, k.it, H(k.salt));
      SecureBinaryData out = kdf.DeriveKey(S(k.pw));
      printf("KDF pw='%s' mem=%u iter=%u salt=%s -> %s\n", k.pw, k.mem, k.it, k.salt, out.toHexStr().c_str());
   }
   // AES-CFB vectors (testPyBtcAddress)
   SecureBinaryData plain = H("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
   SecureBinaryData k1 = H("1111111111111111111111111111111111111111111111111111111111111111");
   SecureBinaryData k2 = H("2222222222222222222222222222222222222222222222222222222222222222");
   SecureBinaryData iv = H("77777777777777777777777777777777");
   printf("CFB k=11.. iv=77.. -> %s\n", CryptoAES().EncryptCFB(plain, k1, iv).toHexStr().c_str());
   printf("CFB k=22.. iv=77.. -> %s\n", CryptoAES().EncryptCFB(plain, k2, iv).toHexStr().c_str());
   // Chained keys
   SecureBinaryData cc = H("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
   SecureBinaryData pub0 = CryptoECDSA().ComputePublicKey(plain);
   SecureBinaryData mult;
   SecureBinaryData p1 = CryptoECDSA().ComputeChainedPrivateKey(plain, cc, pub0, &mult);
   printf("pub0 %s\nhash160(pub0) %s\nmult0 %s\npriv1 %s\n", pub0.toHexStr().c_str(),
          pub0.getHash160().toHexStr().c_str(), mult.toHexStr().c_str(), p1.toHexStr().c_str());
   SecureBinaryData p2 = CryptoECDSA().ComputeChainedPrivateKey(p1, cc);
   printf("priv2 %s\n", p2.toHexStr().c_str());
   SecureBinaryData q1 = CryptoECDSA().ComputeChainedPublicKey(pub0, cc);
   SecureBinaryData q2 = CryptoECDSA().ComputeChainedPublicKey(q1, cc);
   printf("pub1 %s\nhash160(pub1) %s\npub2 %s\n", q1.toHexStr().c_str(), q1.getHash160().toHexStr().c_str(), q2.toHexStr().c_str());
   return 0;
}
