package space.qu4nt.entanglementlib.core.i18n;

import lombok.Getter;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.core.exception.core.ELIBCoreIllegalArgumentException;

import java.util.Locale;
import java.util.MissingResourceException;
import java.util.Objects;
import java.util.ResourceBundle;

public class EntanglementLibCoreI18n {

    private static final String SYSTEM_DEFAULT_BASENAME = "entanglementlib-messages";

    @Getter
    private static Locale locale;
    @Getter
    private static ResourceBundle coreDefaultResourceBundle;
    @Getter
    private static @Nullable ResourceBundle userResourceBundle;

    public static synchronized void initialize(final Locale locale, @Nullable String userResourceBasename) throws ELIBCoreIllegalArgumentException {
        EntanglementLibCoreI18n.locale = Objects.requireNonNull(locale, "locale is null");
        // getLanguage() => ISO 639 alpha2
        try {
            coreDefaultResourceBundle = ResourceBundle.getBundle(SYSTEM_DEFAULT_BASENAME, locale);
        } catch (MissingResourceException e) { // 시스템 기본 국제화 파일을 찾을 수 없음
            throw new ELIBCoreIllegalArgumentException("Could not find 'system default' i18n(" + locale.getLanguage() + ") file");
        }

        // 사용자 지정된 베이스네임 있으면 사용
        if (userResourceBasename != null && !userResourceBasename.isBlank()) {
            try {
                userResourceBundle = ResourceBundle.getBundle(userResourceBasename, locale);
            } catch (MissingResourceException e) { // 사용자 지정 국제화 파일을 찾을 수 없음
                throw new ELIBCoreIllegalArgumentException("Could not find custom i18n(" + locale.getLanguage() + ") file '" + userResourceBasename + "'");
            }
        }
    }

}
