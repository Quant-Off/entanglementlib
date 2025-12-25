/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.resource.control;

import lombok.Getter;
import lombok.Setter;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.resource.ResourceHandler;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;

@Getter
@Setter
public class PublicJSONFileSystemResourceBundleControl extends ResourceHandler {

    private String customDirStringPath;

    public PublicJSONFileSystemResourceBundleControl(String customDirStringPath, Charset streamCharset) {
        super(streamCharset, List.of("json"));
        this.customDirStringPath = customDirStringPath == null ? InternalFactory.envEntanglementPublicDir() : customDirStringPath;
    }

    public PublicJSONFileSystemResourceBundleControl(Charset streamCharset) {
        this(null, streamCharset);
    }

    @Override
    public ResourceBundle newBundle(String baseName,
                                    Locale locale,
                                    String format,
                                    ClassLoader loader,
                                    boolean reload)
            throws IllegalAccessException, InstantiationException, IOException {
        if (!format.equals("json"))
            return super.newBundle(baseName, locale, format, loader, reload);

        String resourceName = baseName + ".json";
        final Path filePath = Paths.get(customDirStringPath + "/" + resourceName);
        try (InputStream stream = Files.newInputStream(filePath);
             InputStreamReader reader = new InputStreamReader(stream, streamCharset)) {
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> map = objectMapper.readValue(reader, new TypeReference<>() {
            });
            Map<String, Object> flatMap = flattenMap(map, "");
            return new YamlResourceBundle(flatMap);
        } catch (IOException e) {
            return null;
        }
    }
}
