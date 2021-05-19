package org.xyyh.oidc.utils;

import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public final class StringCollectionUtils {

    private static final String SPACE_REGEX = "[\\s+]";

    private StringCollectionUtils() {
    }

    public static Set<String> split(String input) {
        if (StringUtils.isBlank(input)) {
            return Collections.emptySet();
        } else {
            return new HashSet<>(Arrays.asList(input.split(SPACE_REGEX)));
        }
    }
}
