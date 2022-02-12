module org.d7z.security4k.core {
    requires kotlin.reflect;
    requires kotlin.stdlib;
    opens org.d7z.security4k.base64;
    exports org.d7z.security4k.base64;
    opens org.d7z.security4k.hash;
    exports org.d7z.security4k.hash;
    opens org.d7z.security4k.asymmetric.rsa;
    exports org.d7z.security4k.asymmetric.rsa;
}
