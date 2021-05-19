package org.xyyh.oidc.utils;

import org.apache.commons.lang3.StringUtils;
import org.xyyh.oidc.collect.CollectionUtils;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

public final class StringCollectionUtils {

    private static final String SPACE_REGEX = "[\\s+]";

    private StringCollectionUtils() {
    }

    public static Set<String> split(Collection<String> input) {
        if (CollectionUtils.isEmpty(input)) {
            return Collections.emptySet();
        } else {
            return input.stream()
                .map(it -> it.split(SPACE_REGEX))
                .flatMap(Arrays::stream)
                .filter(StringUtils::isNotBlank)
                .collect(Collectors.toSet());
        }
    }
}
