/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.resource.config;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.ObjectMapper;

import java.util.Collections;
import java.util.List;
import java.util.ResourceBundle;

/**
 * 구성 파일에서 값을 읽어오는 유틸리티 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public final class Configer {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * 구성에서 정수 값을 불러오는 메소드입니다.
     *
     * @param bundle 기반 리소스 번들
     * @param key    불러오고자 하는 값의 경로
     * @param def    키를 찾을 수 없는 경우의 반환값
     * @return 경로에 위치한 정수 값, 키를 찾을 수 없으면 전달된 기본 값
     */
    public static int getInt(final @NotNull ResourceBundle bundle, final String key, int def) {
        return bundle.containsKey(key) ? (int) bundle.getObject(key) : def;
    }

    /**
     * 구성에서 정수 값을 불러오는 메소드입니다.
     *
     * @param bundle 기반 리소스 번들
     * @param key    불러오고자 하는 값의 경로
     * @return 경로에 위치한 정수 값, 키를 찾을 수 없으면 {@code -1}
     */
    public static int getInt(final @NotNull ResourceBundle bundle, final String key) {
        return getInt(bundle, key, -1);
    }

    /**
     * 구성에서 {@code double} 실수 값을 불러오는 메소드입니다.
     *
     * @param bundle 기반 리소스 번들
     * @param key    불러오고자 하는 값의 경로
     * @param def    키를 찾을 수 없는 경우의 반환값
     * @return 경로에 위치한 {@code double} 실수 값, 키를 찾을 수 없으면 전달된 기본 값
     */
    public static double getDouble(final @NotNull ResourceBundle bundle, final String key, double def) {
        return bundle.containsKey(key) ? (double) bundle.getObject(key) : def;
    }

    /**
     * 구성에서 {@code double} 실수 값을 불러오는 메소드입니다.
     *
     * @param bundle 기반 리소스 번들
     * @param key    불러오고자 하는 값의 경로
     * @return 경로에 위치한 {@code double} 실수 값, 키를 찾을 수 없으면 {@code -1}
     */
    public static double getDouble(final @NotNull ResourceBundle bundle, final String key) {
        return getDouble(bundle, key, -1);
    }

    /**
     * 구성에서 {@code float} 실수 값을 불러오는 메소드입니다.
     *
     * @param bundle 기반 리소스 번들
     * @param key    불러오고자 하는 값의 경로
     * @param def    키를 찾을 수 없는 경우의 반환값
     * @return 경로에 위치한 {@code float} 실수 값, 키를 찾을 수 없으면 전달된 기본 값
     */
    public static float getFloat(final @NotNull ResourceBundle bundle, final String key, float def) {
        return bundle.containsKey(key) ? (float) bundle.getObject(key) : def;
    }

    /**
     * 구성에서 {@code float} 실수 값을 불러오는 메소드입니다.
     *
     * @param bundle 기반 리소스 번들
     * @param key    불러오고자 하는 값의 경로
     * @return 경로에 위치한 {@code float} 실수 값, 키를 찾을 수 없으면 {@code -1}
     */
    public static float getFloat(final @NotNull ResourceBundle bundle, final String key) {
        return getFloat(bundle, key, -1);
    }

    /**
     * 구성에서 논리 값을 불러오는 메소드입니다.
     *
     * @param bundle 기반 리소스 번들
     * @param key    불러오고자 하는 값의 경로
     * @return 경로에 위치한 논리 값, 키를 찾을 수 없으면 false
     */
    public static boolean getBoolean(final @NotNull ResourceBundle bundle, final String key) {
        return bundle.containsKey(key) && (boolean) bundle.getObject(key);
    }

    /**
     * 구성에서 문자열 값을 불러오는 메소드입니다.
     *
     * @param bundle 기반 리소스 번들
     * @param key    불러오고자 하는 값의 경로
     * @param def    키를 찾을 수 없는 경우의 반환값
     * @return 경로에 위치한 문자열 값, 키를 찾을 수 없으면 전달된 기본 값
     */
    @Nullable
    public static String getString(final @NotNull ResourceBundle bundle, final String key, String def) {
        return bundle.containsKey(key) ? bundle.getString(key) : def;
    }

    /**
     * 구성에서 문자열 값을 불러오는 메소드입니다.
     *
     * @param bundle 기반 리소스 번들
     * @param key    불러오고자 하는 값의 경로
     * @return 경로에 위치한 문자열 값, 키를 찾을 수 없으면 {@code null}
     */
    @Nullable
    public static String getString(final @NotNull ResourceBundle bundle, final String key) {
        return getString(bundle, key, null);
    }

    /**
     * 구성에서 오브젝트 배열을 불러오는 메소드입니다.
     * 사용되는 타입은 직접 지정해야 합니다.
     *
     * @param bundle       기반 리소스 번들
     * @param key          불러오고자 하는 값의 경로
     * @param elementClass 타입 지정
     * @param <T>          사용자 정의 타입
     * @return 경로에 위치한 사용자 지정 타입 배열
     */
    public static <T> List<T> getObjectList(final @NotNull ResourceBundle bundle, final String key, @NotNull Class<T> elementClass) {
        String json = bundle.getString(key);
        if (json.trim().isEmpty())
            return Collections.emptyList();
        JavaType type = MAPPER.getTypeFactory().constructCollectionType(List.class, elementClass);
        return MAPPER.readValue(json, type);
    }

    /**
     * 구성에서 {@code Enum} 타입 값을 불러오는 메소드입니다.
     *
     * @param bundle       기반 리소스 번들
     * @param key          불러오고자 하는 값의 경로
     * @param elementClass Enum 클래스 타입
     * @param def          키를 찾을 수 없거나 값이 유효하지 않은 경우의 반환값
     * @param <T>          Enum 타입
     * @return 경로에 위치한 Enum 값, 키를 찾을 수 없거나 유효하지 않으면 전달된 기본 값
     * @throws IllegalArgumentException 기본 값이 {@code null}이고 유효하지 않은 Enum 값일 경우 발생
     */
    @Nullable
    public static <T extends Enum<T>> T getEnumType(final @NotNull ResourceBundle bundle,
                                                    final String key,
                                                    @NotNull Class<T> elementClass,
                                                    final @Nullable T def) {
        if (bundle.containsKey(key)) {
            String enumName = bundle.getString(key);
            try {
                return Enum.valueOf(elementClass, enumName);
            } catch (IllegalArgumentException e) {
                if (def == null)
                    throw new IllegalArgumentException("Invalid enum value for key: " + key + ", value: " + enumName, e);
                return def;
            }
        }
        return def;
    }

    /**
     * 구성에서 {@code Enum} 타입 값을 불러오는 메소드입니다.
     *
     * @param bundle       기반 리소스 번들
     * @param key          불러오고자 하는 값의 경로
     * @param elementClass Enum 클래스 타입
     * @param <T>          Enum 타입
     * @return 경로에 위치한 Enum 값, 키를 찾을 수 없거나 유효하지 않으면 {@code null}
     */
    @Nullable
    public static <T extends Enum<T>> T getEnumType(final @NotNull ResourceBundle bundle,
                                                    final String key,
                                                    @NotNull Class<T> elementClass) {
        return getEnumType(bundle, key, elementClass, null);
    }

}
