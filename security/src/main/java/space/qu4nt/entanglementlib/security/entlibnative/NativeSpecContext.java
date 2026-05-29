package space.qu4nt.entanglementlib.security.entlibnative;

import java.util.Set;

public class NativeSpecContext {

    private String nativeDirName;
    private String nativeFilename;
    private Set<NativeComponent> nativeComponents;

    public NativeSpecContext(String nativeDirName, String nativeFilename, Set<NativeComponent> nativeComponents) {
        this.nativeDirName = nativeDirName;
        this.nativeFilename = nativeFilename;
        this.nativeComponents = nativeComponents;
    }

    public NativeSpecContext(String nativeDirName, String nativeFilename, NativeComponent... nativeComponents) {
        this.nativeDirName = nativeDirName;
        this.nativeFilename = nativeFilename;
        this.nativeComponents = Set.of(nativeComponents);
    }

    public static NativeSpecContext defaults() {
        return new NativeSpecContext("/native", "entlib_native_ffi", Set.of());
    }

    public String getNativeDirName() {
        return nativeDirName;
    }

    public void setNativeDirName(String nativeDirName) {
        this.nativeDirName = nativeDirName;
    }

    public String getNativeFilename() {
        return nativeFilename;
    }

    public void setNativeFilename(String nativeFilename) {
        this.nativeFilename = nativeFilename;
    }

    public Set<NativeComponent> getNativeComponents() {
        return nativeComponents;
    }

    public void setNativeComponents(Set<NativeComponent> nativeComponents) {
        this.nativeComponents = nativeComponents;
    }
}
