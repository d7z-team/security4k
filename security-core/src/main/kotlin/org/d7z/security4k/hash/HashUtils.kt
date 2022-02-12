package org.d7z.security4k.hash

import org.d7z.security4k.api.IStreamCalculate
import org.d7z.security4k.hash.impl.CRC32CHashCalculate
import org.d7z.security4k.hash.impl.CRC32HashCalculate
import org.d7z.security4k.hash.impl.SimpleHashCalculate
import java.io.InputStream
import java.nio.charset.Charset

@Suppress("unused")
object HashUtils {
    /**
     *
     * @property hashCalculate BaseHashCalculate
     * @constructor
     */
    enum class METHOD(val hashCalculate: IStreamCalculate) {
        MD5(SimpleHashCalculate("md5")),
        SHA1(SimpleHashCalculate("sha1")),
        SHA224(SimpleHashCalculate("sha-224")),
        SHA256(SimpleHashCalculate("sha-256")),
        SHA384(SimpleHashCalculate("sha-384")),
        SHA512(SimpleHashCalculate("sha-512")),
        CRC32(CRC32HashCalculate()),
        CRC32C(CRC32CHashCalculate())
    }

    /**
     * 计算流的哈希值
     *
     * @param input InputStream 流
     * @param method METHOD 哈希值算法
     * @return String 哈希值
     */
    fun loadStreamHash(input: InputStream, method: METHOD): String {
        return method.hashCalculate.calculateToText(input)
    }

    /**
     * 获取原始的哈希算法
     */
    fun loadHash(method: METHOD): IStreamCalculate {
        return method.hashCalculate
    }

    /**
     * 计算文本哈希值
     * @param data String 文本
     * @param charset Charset 编码方式
     * @param method METHOD 哈希值算法
     * @return String 哈希值
     */
    fun loadTextHash(data: String, charset: Charset = Charsets.UTF_8, method: METHOD): String {
        return loadStreamHash(data.byteInputStream(charset), method)
    }
}
