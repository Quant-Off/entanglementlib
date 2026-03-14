package space.qu4nt.entanglementlib.security.entlibnative;

import lombok.Getter;
import lombok.Setter;

import java.util.Set;

import static space.qu4nt.entanglementlib.security.entlibnative.NativeComponent.*;

@Getter
@Setter
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
        return new NativeSpecContext("/native", "entlib_native_ffi", Set.of(
                // TODO:
        ));
    }
}
