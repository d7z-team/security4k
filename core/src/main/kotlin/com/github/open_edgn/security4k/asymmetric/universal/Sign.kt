package com.github.open_edgn.security4k.asymmetric.universal

import java.io.InputStream
import java.nio.charset.Charset

/**
 * 签名的接口类
 */
interface Sign {
    /**
     * 数据签名
     *
     * @param input InputStream 被签名数据
     * @param algorithm String 签名算法
     * @return String 签名
     */
    fun sign(input: InputStream, algorithm: String): String

    /**
     *
     * 预设算法的数据签名
     *
     * @param input InputStream 被签名数据
     * @return String 签名
     */
    fun sign(input: InputStream): String

    /**
     * 字符签名
     *
     * @param data String 签名数据
     * @param charset Charset 编码方式
     * @param algorithm String 签名算法
     * @return String 签名
     */
    fun signText(data: String, algorithm: String, charset: Charset = Charsets.UTF_8): String

    /**
     * 预设算法的字符签名
     *
     * @param data String 签名数据
     * @param charset Charset 编码
     * @return String 签名
     */
    fun signText(data: String, charset: Charset = Charsets.UTF_8): String


}