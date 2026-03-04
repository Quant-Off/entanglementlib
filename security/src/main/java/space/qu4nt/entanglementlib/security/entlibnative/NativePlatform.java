package space.qu4nt.entanglementlib.security.entlibnative;

import java.util.Locale;

public enum NativePlatform {

    WINDOWS("", ".dll"),
    LINUX("lib", ".so"),
    MACOS("lib", ".dylib"),
    UNKNOWN("", "");

    private final String prefix;
    private final String extension;

    NativePlatform(String prefix, String extension) {
        this.prefix = prefix;
        this.extension = extension;
    }

    public static NativePlatform detectOs() {
        String osName = System.getProperty("os.name").toLowerCase(Locale.ENGLISH);
        if (osName.contains("win")) return WINDOWS;
        if (osName.contains("mac") || osName.contains("darwin")) return MACOS;
        if (osName.contains("nix") || osName.contains("nux") || osName.contains("aix")) return LINUX;
        return UNKNOWN;
    }

    public static String detectArchitecture() {
        String arch = System.getProperty("os.arch").toLowerCase(Locale.ENGLISH);
        if (arch.contains("amd64") || arch.contains("x86_64")) return "x86_64";
        if (arch.contains("aarch64") || arch.contains("arm64")) return "aarch64";
        return arch; // 기타 아키텍처 (필요시 확장)
    }

    public String buildFileName(String baseName) {
        return this.prefix + baseName + this.extension;
    }
}