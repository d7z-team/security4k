package com.github.open_edgn.security4k.hash

import java.io.InputStream

interface BaseHashCalculate {
    /**
     * 此哈希值算法名称
     */
    abstract val name: String

    /**
     * 计算哈希值
     * @param input InputStream 被计算的流
     * @return String 哈希值信息
     */
    abstract fun calculate(input: InputStream): String



}