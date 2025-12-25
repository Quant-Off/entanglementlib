/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.resource.config;

import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.List;
import java.util.ResourceBundle;

@Getter
@Setter
public class ConfigerInstanceBased {

    private ResourceBundle bundle;

    private ConfigerInstanceBased(@NotNull ResourceBundle bundle) {
        this.bundle = bundle;
    }

    public static ConfigerInstanceBased of(@NotNull ResourceBundle bundle) {
        return new ConfigerInstanceBased(bundle);
    }

    public int getInt(String key) {
        return Configer.getInt(bundle, key);
    }

    public int getInt(String key, int def) {
        return Configer.getInt(bundle, key, def);
    }

    public double getDouble(String key) {
        return Configer.getDouble(bundle, key);
    }

    public double getDouble(String key, double def) {
        return Configer.getDouble(bundle, key, def);
    }

    public float getFloat(String key) {
        return Configer.getFloat(bundle, key);
    }

    public float getFloat(String key, float def) {
        return Configer.getFloat(bundle, key, def);
    }

    public boolean getBoolean(String key) {
        return Configer.getBoolean(bundle, key);
    }

    public String getString(String key, String def) {
        return Configer.getString(bundle, key, def);
    }

    public String getString(String key) {
        return Configer.getString(bundle, key);
    }

    public List<String> getStringList(String key) {
        return Configer.getObjectList(bundle, key, String.class);
    }

    public <T> List<T> getObjectList(String key, Class<T> elementClass) {
        return Configer.getObjectList(bundle, key, elementClass);
    }

    public <T extends Enum<T>> T getEnumType(String key, Class<T> elementClass, final @Nullable T def) {
        return Configer.getEnumType(bundle, key, elementClass, def);
    }

    public <T extends Enum<T>> T getEnumType(String key, Class<T> elementClass) {
        return Configer.getEnumType(bundle, key, elementClass);
    }

}
