package org.xzcode.oidc.test;

import org.junit.jupiter.api.Test;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

public class TestMult {

    @Test
    public void test() {
        MultiValueMap<String, String> r = new LinkedMultiValueMap<>();
        r.set("b", "");
        System.out.println(r.get("b"));
    }

    @Test
    public void testIntern() {
        String a = new String("test");
        String b = new String("test");
        System.out.println(a == b);
        String c = a.intern();
        String d = b.intern();
        System.out.println(c == d);
    }
}
