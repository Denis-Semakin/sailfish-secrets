#ifndef _TK26_H
#define _TK26_H

/* TK26 constants */
#define NSSCK_VENDOR_PKCS11_RU_TEAM             0xD4321000 /* 0x80000000 | 0x54321000 */
#define CK_VENDOR_PKCS11_RU_TEAM_TC26           NSSCK_VENDOR_PKCS11_RU_TEAM

#define CKK_GOSTR3410_256                       CKK_GOSTR3410
#define CKK_GOSTR3410_512                       (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x003)
#define CKK_KUZNECHIK                           (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x004)

#define CKA_GOSTR3410_256PARAMS                 CKA_GOSTR3410_PARAMS
#define CKA_GOSTR3410_512PARAMS                 (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x004)

#define CKP_PKCS5_PBKD2_HMAC_GOSTR3411_2012_256 (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x002)
#define CKP_PKCS5_PBKD2_HMAC_GOSTR3411_2012_512 (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x003)

#define CKM_GOSTR3410_256_KEY_PAIR_GEN          CKM_GOSTR3410_KEY_PAIR_GEN
#define CKM_GOSTR3410_256                       CKM_GOSTR3410

#define CKM_GOSTR3410_512_KEY_PAIR_GEN          (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x005)
#define CKM_GOSTR3410_512                       (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x006)

#define CKM_GOSTR3410_2012_DERIVE               (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x007)
#define CKM_GOSTR3410_12_DERIVE                 CKM_GOSTR3410_2012_DERIVE

#define CKM_GOSTR3410_WITH_GOSTR3411_94         CKM_GOSTR3410_WITH_GOSTR3411
#define CKM_GOSTR3410_WITH_GOSTR3411_2012_256   (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x008)
#define CKM_GOSTR3410_WITH_GOSTR3411_12_256     CKM_GOSTR3410_WITH_GOSTR3411_2012_256
#define CKM_GOSTR3410_WITH_GOSTR3411_2012_512   (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x009)
#define CKM_GOSTR3410_WITH_GOSTR3411_12_512     CKM_GOSTR3410_WITH_GOSTR3411_2012_512

#define CKM_GOSTR3410_PUBLIC_KEY_DERIVE         (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x00A)

#define CKM_GOSTR3411_94                        CKM_GOSTR3411
#define CKM_GOSTR3411_2012_256                  (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x012)
#define CKM_GOSTR3411_12_256                    CKM_GOSTR3411_2012_256
#define CKM_GOSTR3411_2012_512                  (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x013)
#define CKM_GOSTR3411_12_512                    CKM_GOSTR3411_2012_512

#define CKM_GOSTR3411_94_HMAC                   CKM_GOSTR3411_HMAC
#define CKM_GOSTR3411_2012_256_HMAC             (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x014)
#define CKM_GOSTR3411_12_256_HMAC               CKM_GOSTR3411_2012_256_HMAC
#define CKM_GOSTR3411_2012_512_HMAC             (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x015)
#define CKM_GOSTR3411_12_512_HMAC               CKM_GOSTR3411_2012_512_HMAC

#define CKM_TLS_GOST_PRF_2012_256               (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x016)
#define CKM_TLS_GOST_PRF_2012_512               (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x017)

#define CKM_KUZNECHIK_KEY_GEN                   (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x019)
#define CKM_KUZNECHIK_ECB                       (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x01A)
#define CKM_KUZNECHIK_CTR                       (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x01B)
#define CKM_KUZNECHIK_CFB                       (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x01C)
#define CKM_KUZNECHIK_OFB                       (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x01D)
#define CKM_KUZNECHIK_CBC                       (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x01E)
#define CKM_KUZNECHIK_MAC                       (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x01F)

#define CKM_MAGMA_ECB                           CKM_GOST28147_ECB
#define CKM_MAGMA_CTR                           (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x020)
#define CKM_MAGMA_CFB                           (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x021)
#define CKM_MAGMA_OFB                           (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x022)
#define CKM_MAGMA_CBC                           (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x023)
#define CKM_MAGMA_MAC                           (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x024)

#define CKM_KDF_4357                            (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x025)
#define CKM_KDF_GOSTR3411_2012_256              (CK_VENDOR_PKCS11_RU_TEAM_TC26 | 0x026)

#endif /* _TK26_H */

