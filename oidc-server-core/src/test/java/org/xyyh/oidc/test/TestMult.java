package org.xyyh.oidc.test;

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
}
