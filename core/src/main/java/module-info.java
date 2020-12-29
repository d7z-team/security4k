module security4k.core {
    requires kotlin.reflect;
    requires kotlin.stdlib;
    opens com.github.open_edgn.security4k.base64;
    exports com.github.open_edgn.security4k.base64;
    opens com.github.open_edgn.security4k.hash;
    exports com.github.open_edgn.security4k.hash;
    opens com.github.open_edgn.security4k.asymmetric.rsa;
    exports com.github.open_edgn.security4k.asymmetric.rsa;
}