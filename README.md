# Simple compile

gcc -O2  sm2_sign_and_verify.c sm3_with_preprocess.c sm2_create_key_pair.c test_sm2_sign_and_verify.c test_demo.c  -ldl -lssl -lcrypto

Attention: need openssl libary

# SM2-signature-creation-and-verification
&ensp;&ensp;&ensp;&ensp;An implementation of SM2 signature creation and verification is provided. Header files and library files of OpenSSL 1.1.1 or higher version are needed while compiling and linking. OpenSSL website is: https://www.openssl.org

&ensp;&ensp;&ensp;&ensp;SM2 is a cryptographic algorithm based on elliptic curves. It is defined in the following standards of China:
- GB/T32918.1-2016,
- GB/T32918.2-2016,
- GB/T32918.3-2016,
- GB/T32918.4-2016,
- GM/T 0003-2012.  

&ensp;&ensp;&ensp;&ensp;SM2 signature creation and verification are supported in OpenSSL 1.1.1. In the source package, "/crypto/sm2/sm2_sign.c" is a good example. Digital signature creation and verification are encapsulated in an abstract level called EVP. In some cases using EVP interfaces to compute SM2 signature and verify it is a little inconvenient. An implementation bypassing invoking OpenSSL EVP interfaces is given here.
