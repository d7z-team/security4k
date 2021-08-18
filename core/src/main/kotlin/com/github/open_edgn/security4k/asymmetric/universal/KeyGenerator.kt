package com.github.open_edgn.security4k.asymmetric.universal

/**
 * 密钥生成器
 */
interface KeyGenerator {
    /**
     *  公钥文本
     */
    val publicKeyText: String

    /**
     * 私钥文本
     */
    val privateKeyText: String
}
