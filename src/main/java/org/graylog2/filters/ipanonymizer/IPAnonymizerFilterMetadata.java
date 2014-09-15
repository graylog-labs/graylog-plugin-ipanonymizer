package org.graylog2.filters.ipanonymizer;

import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.Version;

import java.net.URI;

public class IPAnonymizerFilterMetadata implements PluginMetaData {
    @Override
    public String getUniqueId() {
        return IPAnonymizerFilter.class.getCanonicalName();
    }

    @Override
    public String getName() {
        return "IPv4 address anonymizing filter";
    }

    @Override
    public String getAuthor() {
        return "TORCH GmbH";
    }

    @Override
    public URI getURL() {
        return URI.create("http://www.torch.sh");
    }

    @Override
    public Version getVersion() {
        return new Version(0, 21, 0);
    }

    @Override
    public String getDescription() {
        return "Filter plugin that anonymizes IPv4 addresses by replacing the last octet with 'XXX'.";
    }

    @Override
    public Version getRequiredVersion() {
        return new Version(0, 21, 0);
    }
}
