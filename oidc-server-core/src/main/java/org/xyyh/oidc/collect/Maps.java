package org.xyyh.oidc.collect;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public final class Maps {
    private Maps() {
    }

    public static boolean isEmpty(final Map<?, ?> map) {
        return map == null || map.isEmpty();
    }

    public static boolean isNotEmpty(final Map<?, ?> map) {
        return !isEmpty(map);
    }

    public static <K, V> HashMap<K, V> hashMap(K key, V value) {
        HashMap<K, V> result = new HashMap<>();
        result.put(key, value);
        return result;
    }

    public static <K, V> Map<K, V> hashMap() {
        return new HashMap<>();
    }

    public static <K, V> Map<K, V> hashMap(Map<K, V> map) {
        return map == null ? new HashMap<>() : new HashMap<>(map);
    }

    public static <K, V> LinkedHashMap<K, V> linkedHashMap() {
        return new LinkedHashMap<>();
    }
}
