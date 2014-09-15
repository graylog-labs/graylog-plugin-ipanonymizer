package org.graylog2.filters.ipanonymizer;

import org.graylog2.plugin.Plugin;
import org.graylog2.plugin.PluginModule;

import java.util.Collection;
import java.util.Collections;

public class IPAnonymizerFilterPlugin implements Plugin {
    @Override
    public Collection<PluginModule> modules() {
        return Collections.<PluginModule>singleton(new IPAnonymizerFilterModule());
    }
}
