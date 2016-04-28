package org.graylog2.filters.ipanonymizer;

import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.Version;

import java.net.URI;
import java.util.Collections;
import java.util.Set;

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
        return "Graylog, Inc.";
    }

    @Override
    public URI getURL() {
        return URI.create("http://www.graylog.org/");
    }

    @Override
    public Version getVersion() {
        return new Version(1, 2, 0);
    }

    @Override
    public String getDescription() {
        return "Filter plugin that anonymizes IPv4 addresses by replacing the last octet with 'XXX'.";
    }

    @Override
    public Version getRequiredVersion() {
        return new Version(2, 0, 0);
    }

    @Override
    public Set<ServerStatus.Capability> getRequiredCapabilities() {
        return Collections.emptySet();
    }
}
