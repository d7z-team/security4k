package org.d7z.security4k.asymmetric.universal

import org.d7z.security4k.universal.Encrypt

/**
 * 非对称加解密中公钥接口
 */
interface IPublicKey : Encrypt, Verify
