package org.d7z.security4k.asymmetric.universal

import java.io.InputStream
import java.nio.charset.Charset

/**
 * 数据校验接口
 */
interface Verify {
    /**
     * 数据校验
     *
     * @param input InputStream 被校验的流数据
     * @param signText String 数据签名
     * @param algorithm String 校验算法
     * @return Boolean 校验结果
     */
    fun verify(input: InputStream, signText: String, algorithm: String): Boolean

    /**
     * 预设算法的数据校验
     *
     * @param input InputStream 被校验的流数据
     * @param signText String 数据签名
     * @return Boolean 校验结果
     */
    fun verify(input: InputStream, signText: String): Boolean

    /**
     * 文字校验
     *
     * @param data String 被校验的流数据
     * @param signText String 数据签名
     * @param algorithm String 校验算法
     * @return Boolean 校验结果
     */
    fun verifyText(data: String, signText: String, algorithm: String, charset: Charset = Charsets.UTF_8): Boolean

    /**
     * 预设算法的文字校验
     *
     * @param data String 被校验的流数据
     * @param signText String 数据签名
     * @return Boolean 校验结果
     */
    fun verifyText(data: String, signText: String, charset: Charset = Charsets.UTF_8): Boolean
}
