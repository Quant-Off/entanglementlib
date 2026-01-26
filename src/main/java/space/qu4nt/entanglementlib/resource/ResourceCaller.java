/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.resource;

import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.resource.control.PublicJSONFileSystemResourceBundleControl;
import space.qu4nt.entanglementlib.resource.control.PublicYamlFileSystemResourceBundleControl;
import space.qu4nt.entanglementlib.util.io.EntFile;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.ObjectReader;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * 리소스 번들의 소스를 관리하는 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Slf4j
public final class ResourceCaller {

    /**
     * 프로젝트가 사용하는 리소스 번들의 경로를 사용자 지정하고자 하는 경우에
     * 사용되는 메소드입니다.
     *
     * @param format              리소스 파일 포멧(확장자)
     * @param customDirStringPath 리소스 디렉토리
     * @param baseName            리소스 디렉토리에 포함된 리소스 (확장자 없는) 파일 이름
     * @param streamCharset       리소스 로드에 사용할 {@link Charset}
     * @return 지정된 경로의 파일로 정의된 {@link ResourceBundle}
     */
    public static ResourceBundle getCustomResourceBundle(final SupportedFormat format, final String customDirStringPath, final String baseName, Charset streamCharset) {
        try {
            Path path = Paths.get(customDirStringPath);
            Files.createDirectories(path);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        ResourceBundle.Control ctrl =
                switch (format) {
                    case YAML -> new PublicYamlFileSystemResourceBundleControl(customDirStringPath, streamCharset);
                    case JSON -> new PublicJSONFileSystemResourceBundleControl(customDirStringPath, streamCharset);
                };
        ResourceBundle bundle = ResourceBundle.getBundle(baseName, Locale.getDefault(), ctrl);
        // NOTE: 어째서 파일은 있고 엔트리가 없어도 MissingResourceException 예외가 발생하는 것인가? null 체크가 의미 없는 것인가...?
        if (bundle == null)
            throw new MissingResourceException(baseName, customDirStringPath, null);
        if (bundle.getKeys().nextElement() == null)
            log.warn("No keys found in {}", baseName);
        return bundle;
    }

    /**
     * 프로젝트가 사용하는 리소스 번들의 경로를 사용자 지정된 디렉토리로 결정하고,
     * 리소스 파일을 사용자 지정하고자 하는 경우에 사용되는 메소드입니다.
     * <p>
     * 디렉토리를 설정하기 위해 {@code ENTANGLEMENT_PUBLIC_DIR} 환경 변수에 사용자 지정된
     * 디렉토리 위치를 정의해야 합니다.
     *
     * @param baseName      리소스 디렉토리에 포함된 리소스 (확장자 없는) 파일 이름
     * @param streamCharset 리소스 로드에 사용할 {@link Charset}
     * @return 지정된 경로의 파일로 정의된 {@link ResourceBundle}
     */
    public static ResourceBundle getCustomResourceInPublic(final SupportedFormat format, final String baseName, Charset streamCharset) {
        return getCustomResourceBundle(format, InternalFactory.envEntanglementPublicDir(), baseName, streamCharset);
    }

    /**
     * 프로젝트가 사용하는 리소스 번들의 경로를 사용자 지정된 디렉토리 하위에서
     * 사용자 지정하고자 하는 경우에 사용되는 메소드입니다.
     * <p>
     * 디렉토리를 설정하기 위해 {@code ENTANGLEMENT_PUBLIC_DIR} 환경 변수에 사용자 지정된
     * 디렉토리 위치를 정의해야 합니다.
     *
     * @param inPublicDirName 공개 디렉토리 내의 하위 디렉토리 이름
     * @param baseName        디렉토리 하위에 포함된 리소스 (확장자 없는) 파일 이름
     * @param streamCharset   리소스 로드에 사용할 {@link Charset}
     * @return 지정된 경로의 파일로 정의된 {@link ResourceBundle}
     */
    public static ResourceBundle getCustomResourceInPublicInnerDir(final SupportedFormat format, final String inPublicDirName, final String baseName, Charset streamCharset) {
        String path = Paths.get(InternalFactory.envEntanglementPublicDir()).resolve(inPublicDirName).toString();
        return getCustomResourceBundle(format, path, baseName, streamCharset);
    }

    /**
     * 지정된 공개 디렉토리 하위 파일을 Jackson 라이브러리를 사용하여 역직렬화합니다.
     * 이 메소드는 파일의 복합 보안 검증(트래버셜, 무결성)을 수행하지 않습니다.
     *
     * @param mapper   사용할 {@link ObjectMapper} 인스턴스
     * @param filename 디렉토리 하위에 포함된 역직렬화할 파일 이름
     * @param ref      역직렬화될 객체의 {@link Class} 타입
     * @param <T>      역직렬화될 객체의 타입
     * @return 역직렬화된 객체
     * @throws IOException 읽기 작업 중 문제가 발생한 경우
     */
    public static <T> T jacksonDeserializeInPublic(@NotNull ObjectMapper mapper, final @NotNull String filename, @NotNull Class<T> ref)
            throws IOException {
        Path filePath = Paths.get(InternalFactory.envEntanglementPublicDir()).resolve(filename);
        try (InputStream is = EntFile.Unchecked.openStream(filePath)) {
            return deserializeWithStream(mapper, is, ref);
        }
    }

    /**
     * 지정된 공개 디렉토리 하위 디렉토리의 파일을 Jackson 라이브러리를 사용하여 역직렬화합니다.
     * 이 메소드는 파일의 복합 보안 검증(트래버셜, 무결성)을 수행하지 않습니다.
     *
     * @param mapper          사용할 {@link ObjectMapper} 인스턴스
     * @param inPublicDirName 공개 디렉토리 내의 하위 디렉토리 이름
     * @param filename        디렉토리 하위에 포함된 역직렬화할 파일 이름
     * @param ref             역직렬화될 객체의 {@link Class} 타입
     * @param <T>             역직렬화될 객체의 타입
     * @return 역직렬화된 객체
     * @throws IOException 읽기 작업 중 문제가 발생한 경우
     */
    public static <T> T jacksonDeserializeInPublicInnerDir(@NotNull ObjectMapper mapper, @NotNull String inPublicDirName, @NotNull String filename, @NotNull Class<T> ref)
            throws IOException {
        Path filePath = Paths.get(InternalFactory.envEntanglementPublicDir()).resolve(inPublicDirName).resolve(filename);
        try (InputStream is = EntFile.Unchecked.openStream(filePath)) {
            return deserializeWithStream(mapper, is, ref);
        }
    }

    /**
     * {@link InputStream}에서 데이터를 읽어와 Jackson 라이브러리를 사용하여 역직렬화합니다.
     * 이 메소드는 스트림을 효율적으로 처리하며, 전체 내용을 메모리에 로드하지 않습니다.
     *
     * @param mapper      사용할 {@link ObjectMapper} 인스턴스
     * @param inputStream 역직렬화할 데이터의 입력 스트림
     * @param ref         역직렬화될 객체의 {@link Class} 타입
     * @param <T>         역직렬화될 객체의 타입
     * @return 역직렬화된 객체
     */
    private static <T> T deserializeWithStream(ObjectMapper mapper, InputStream inputStream, Class<T> ref) {
        ObjectReader reader = mapper.readerFor(ref);
        // JsonParser가 InputStream을 소비함 (전체 로드 X)
        try (JsonParser parser = mapper.createParser(inputStream)) {
            return reader.readValue(parser);
        }
    }
}
