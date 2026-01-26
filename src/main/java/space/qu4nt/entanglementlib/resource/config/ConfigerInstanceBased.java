/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.resource.config;

import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.List;
import java.util.ResourceBundle;

/**
 * 인스턴스 기반으로 구성 파일에서 값을 읽어오는 클래스입니다.
 * <p>
 * 이 클래스를 상속하여 구성 리소스 번들을 등록하고 자유롭게 호출하여
 * 사용할 수도 있습니다
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Getter
@Setter
public class ConfigerInstanceBased {

    private ResourceBundle bundle;

    /**
     * {@link ConfigerInstanceBased} 객체를 생성합니다.
     *
     * @param bundle 리소스 번들
     */
    protected ConfigerInstanceBased(@NotNull ResourceBundle bundle) {
        this.bundle = bundle;
    }

    /**
     * 주어진 리소스 번들로 {@link ConfigerInstanceBased} 인스턴스를 생성합니다.
     *
     * @param bundle 리소스 번들
     * @return ConfigerInstanceBased 인스턴스
     */
    public static ConfigerInstanceBased of(@NotNull ResourceBundle bundle) {
        return new ConfigerInstanceBased(bundle);
    }

    /**
     * 구성에서 정수 값을 불러오는 메소드입니다.
     *
     * @param key 불러오고자 하는 값의 경로
     * @return 경로에 위치한 정수 값
     */
    public int getInt(String key) {
        return Configer.getInt(bundle, key);
    }

    /**
     * 구성에서 정수 값을 불러오는 메소드입니다.
     *
     * @param key 불러오고자 하는 값의 경로
     * @param def 키를 찾을 수 없는 경우의 반환값
     * @return 경로에 위치한 정수 값, 키를 찾을 수 없으면 전달된 기본 값
     */
    public int getInt(String key, int def) {
        return Configer.getInt(bundle, key, def);
    }

    /**
     * 구성에서 {@code double} 실수 값을 불러오는 메소드입니다.
     *
     * @param key 불러오고자 하는 값의 경로
     * @return 경로에 위치한 {@code double} 실수 값
     */
    public double getDouble(String key) {
        return Configer.getDouble(bundle, key);
    }

    /**
     * 구성에서 {@code double} 실수 값을 불러오는 메소드입니다.
     *
     * @param key 불러오고자 하는 값의 경로
     * @param def 키를 찾을 수 없는 경우의 반환값
     * @return 경로에 위치한 {@code double} 실수 값, 키를 찾을 수 없으면 전달된 기본 값
     */
    public double getDouble(String key, double def) {
        return Configer.getDouble(bundle, key, def);
    }

    /**
     * 구성에서 {@code float} 실수 값을 불러오는 메소드입니다.
     *
     * @param key 불러오고자 하는 값의 경로
     * @return 경로에 위치한 {@code float} 실수 값
     */
    public float getFloat(String key) {
        return Configer.getFloat(bundle, key);
    }

    /**
     * 구성에서 {@code float} 실수 값을 불러오는 메소드입니다.
     *
     * @param key 불러오고자 하는 값의 경로
     * @param def 키를 찾을 수 없는 경우의 반환값
     * @return 경로에 위치한 {@code float} 실수 값, 키를 찾을 수 없으면 전달된 기본 값
     */
    public float getFloat(String key, float def) {
        return Configer.getFloat(bundle, key, def);
    }

    /**
     * 구성에서 논리 값을 불러오는 메소드입니다.
     *
     * @param key 불러오고자 하는 값의 경로
     * @return 경로에 위치한 논리 값
     */
    public boolean getBoolean(String key) {
        return Configer.getBoolean(bundle, key);
    }

    /**
     * 구성에서 문자열 값을 불러오는 메소드입니다.
     *
     * @param key 불러오고자 하는 값의 경로
     * @param def 키를 찾을 수 없는 경우의 반환값
     * @return 경로에 위치한 문자열 값, 키를 찾을 수 없으면 전달된 기본 값
     */
    public String getString(String key, String def) {
        return Configer.getString(bundle, key, def);
    }

    /**
     * 구성에서 문자열 값을 불러오는 메소드입니다.
     *
     * @param key 불러오고자 하는 값의 경로
     * @return 경로에 위치한 문자열 값
     */
    public String getString(String key) {
        return Configer.getString(bundle, key);
    }

    /**
     * 구성에서 문자열 리스트를 불러오는 메소드입니다.
     *
     * @param key 불러오고자 하는 값의 경로
     * @return 경로에 위치한 문자열 리스트
     */
    public List<String> getStringList(String key) {
        return Configer.getObjectList(bundle, key, String.class);
    }

    /**
     * 구성에서 오브젝트 리스트를 불러오는 메소드입니다.
     *
     * @param key          불러오고자 하는 값의 경로
     * @param elementClass 요소의 클래스 타입
     * @param <T>          요소의 타입
     * @return 경로에 위치한 오브젝트 리스트
     */
    public <T> List<T> getObjectList(String key, Class<T> elementClass) {
        return Configer.getObjectList(bundle, key, elementClass);
    }

    /**
     * 구성에서 {@code Enum} 타입 값을 불러오는 메소드입니다.
     *
     * @param key          불러오고자 하는 값의 경로
     * @param elementClass Enum 클래스 타입
     * @param def          키를 찾을 수 없거나 값이 유효하지 않은 경우의 반환값
     * @param <T>          Enum 타입
     * @return 경로에 위치한 Enum 값, 키를 찾을 수 없거나 유효하지 않으면 전달된 기본 값
     */
    public <T extends Enum<T>> T getEnumType(String key, Class<T> elementClass, final @Nullable T def) {
        return Configer.getEnumType(bundle, key, elementClass, def);
    }

    /**
     * 구성에서 Enum 타입 값을 불러오는 메소드입니다.
     *
     * @param key          불러오고자 하는 값의 경로
     * @param elementClass Enum 클래스 타입
     * @param <T>          Enum 타입
     * @return 경로에 위치한 Enum 값
     */
    public <T extends Enum<T>> T getEnumType(String key, Class<T> elementClass) {
        return Configer.getEnumType(bundle, key, elementClass);
    }

}
