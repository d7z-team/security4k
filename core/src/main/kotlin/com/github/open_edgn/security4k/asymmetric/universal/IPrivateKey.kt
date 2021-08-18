package com.github.open_edgn.security4k.asymmetric.universal

import com.github.open_edgn.security4k.universal.Encrypt

/**
 * 非对称加、解密中私钥的接口
 */
interface IPrivateKey : Encrypt, Sign
