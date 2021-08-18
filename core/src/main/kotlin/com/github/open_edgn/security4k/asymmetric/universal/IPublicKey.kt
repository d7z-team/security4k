package com.github.open_edgn.security4k.asymmetric.universal

import com.github.open_edgn.security4k.universal.Encrypt

/**
 * 非对称加解密中公钥接口
 */
interface IPublicKey : Encrypt, Verify
