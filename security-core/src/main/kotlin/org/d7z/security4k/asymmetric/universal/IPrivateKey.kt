package org.d7z.security4k.asymmetric.universal

import org.d7z.security4k.universal.Encrypt

/**
 * 非对称加、解密中私钥的接口
 */
interface IPrivateKey : Encrypt, Sign
