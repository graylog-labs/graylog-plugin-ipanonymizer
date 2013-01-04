/**
 * Copyright 2013 Lennart Koopmann <lennart@socketfeed.com>
 *
 * This file is part of Graylog2.
 *
 * Graylog2 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Graylog2 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Graylog2.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
package org.graylog2.ipanonymizerfilter.filter;

import java.util.Map;
import java.util.regex.Pattern;
import org.graylog2.plugin.GraylogServer;
import org.graylog2.plugin.filters.MessageFilter;
import org.graylog2.plugin.logmessage.LogMessage;

/**
 * @author Lennart Koopmann <lennart@socketfeed.com>
 */
public class IPAnonymizerFilter implements MessageFilter {

    public static final String NAME = "IP anonymizer";
    
    public static final String REPLACEMENT = "$1.$2.$3.xxx";
    
    private static final Pattern p = Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})");
    
    public boolean filter(LogMessage msg, GraylogServer server) {
        msg.setShortMessage(anonymize(msg.getShortMessage()));
        msg.setFullMessage(anonymize(msg.getFullMessage()));
        
        for (Map.Entry<String, Object> a : msg.getAdditionalData().entrySet()) {
            if (a.getValue() instanceof String) {
                msg.setAdditionalData(a.getKey(), anonymize((String) a.getValue()));
            }
        }
        
        // Never filter out a message.
        return false;
    }

    public String getName() {
        return NAME;
    }
    
    private String anonymize(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        
        return p.matcher(input).replaceAll(REPLACEMENT);
    }
    
}
