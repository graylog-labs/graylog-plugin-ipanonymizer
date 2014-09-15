package org.graylog2.filters.ipanonymizer;

import org.graylog2.plugin.PluginModule;

public class IPAnonymizerFilterModule extends PluginModule {
    @Override
    protected void configure() {
        registerPlugin(IPAnonymizerFilterMetadata.class);
        addMessageFilter(IPAnonymizerFilter.class);
    }
}
