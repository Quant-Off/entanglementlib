/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.resource.control;

import lombok.Getter;
import lombok.Setter;
import org.yaml.snakeyaml.Yaml;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.resource.ResourceHandler;

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
public class PublicYamlFileSystemResourceBundleControl extends ResourceHandler {

    private String customDirStringPath;

    public PublicYamlFileSystemResourceBundleControl(String customDirStringPath, Charset streamCharset) {
        super(streamCharset, List.of("yaml"));
        this.customDirStringPath = customDirStringPath == null ? InternalFactory.envEntanglementPublicDir() : customDirStringPath;
    }

    public PublicYamlFileSystemResourceBundleControl(Charset streamCharset) {
        this(null, streamCharset);
    }

    @Override
    public ResourceBundle newBundle(String baseName,
                                    Locale locale,
                                    String format,
                                    ClassLoader loader,
                                    boolean reload)
            throws IllegalAccessException, InstantiationException, IOException {
        if (!format.equals("yaml"))
            return super.newBundle(baseName, locale, format, loader, reload);

        String resourceName = baseName + ".yml";
        final Path filePath = Paths.get(customDirStringPath + "/" + resourceName);
        try (InputStream stream = Files.newInputStream(filePath);
             InputStreamReader reader = new InputStreamReader(stream, streamCharset)) {
            Yaml yaml = new Yaml();
            Map<String, Object> map = yaml.load(reader);
            Map<String, Object> flatMap = flattenMap(map, "");
            return new YamlResourceBundle(flatMap);
        } catch (IOException e) {
            return null;
        }
    }
}
