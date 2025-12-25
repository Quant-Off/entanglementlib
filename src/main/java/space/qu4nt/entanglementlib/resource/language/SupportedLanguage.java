/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.resource.language;

import lombok.Getter;

/**
 * 현재 프로젝트가 지원하는 언어입니다. 새로운 언어를 추가하고자 하는 경우, {@code i18n}에 따라
 * 국적에 맞는 열거 상수를 추가한 뒤, 공용 리소스 디렉토리에 {@code messages_en_US.yml}와 같이
 * 언어 파일을 생성하세요.
 * <p>
 * ISO 3166-1 에 따른 국가 코드, ISO 639-1 에 따른 언어 코드 양식을 준수하세요.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Getter
public enum SupportedLanguage {

    /**
     * 한국어
     */
    ko_KR,
    /**
     * US English
     */
    en_US;

    private final String filename = "messages_" + name();

}
