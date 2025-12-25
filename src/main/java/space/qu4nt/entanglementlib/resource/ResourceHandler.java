/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.resource;

import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.Charset;
import java.util.*;

public abstract class ResourceHandler extends ResourceBundle.Control {

    @Setter
    @Getter
    protected Charset streamCharset;

    private final List<String> formats;

    public ResourceHandler(Charset streamCharset, final List<String> formats) {
        this.streamCharset = streamCharset;
        this.formats = formats;
    }

    @Override
    public List<String> getFormats(String baseName) {
        return formats;
    }

    /**
     * 중첩된 Map을 평평한 키-값 구조로 변환하는 헬퍼 메소드입니다.
     * <p>
     * {@code YAML} 형식의 파일인 경우, 계층 구조를 받아 {@code .}으로
     * 구분하기 위해 사용됩니다.
     *
     * @param map    타겟 Map
     * @param prefix 접두사
     * @return 평평한 키-값 구조 Map
     */
    public Map<String, Object> flattenMap(Map<String, Object> map, String prefix) {
        Map<String, Object> flat = new HashMap<>();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            String key = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
            Object value = entry.getValue();
            if (value instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> nestedMap = (Map<String, Object>) value;
                flat.putAll(flattenMap(nestedMap, key));
            } else {
                flat.put(key, value);
            }
        }
        return flat;
    }

    /**
     * YAML 데이터를 위한 커스텀 {@link ResourceBundle} 구현체 클래스입니다.
     *
     * @author Q. T. Felix
     * @since 1.0.0
     */
    public static class YamlResourceBundle extends ResourceBundle {
        private final Map<String, Object> map;

        public YamlResourceBundle(Map<String, Object> map) {
            this.map = map;
        }

        @Override
        protected Object handleGetObject(@NotNull String key) {
            return map.get(key);
        }

        @Override
        public @NotNull Enumeration<String> getKeys() {
            return Collections.enumeration(map.keySet());
        }
    }

}
