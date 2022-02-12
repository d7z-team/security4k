package org.d7z.security4k.api

/**
 * 密钥生成器
 */
interface IKeyGenerator {
    /**
     *  公钥文本
     */
    val publicKeyText: String

    /**
     * 私钥文本
     */
    val privateKeyText: String
}
