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
package org.graylog2.filters.ipanonymizer;

import org.graylog2.plugin.Message;
import org.graylog2.plugin.filters.MessageFilter;

import java.util.Map;
import java.util.regex.Pattern;

import static com.google.common.base.Strings.isNullOrEmpty;

/**
 * A Graylog2 {@link MessageFilter} which anonymizes IPv4 addresses
 * by replacing the last octet with {@literal xxx}.
 */
public class IPAnonymizerFilter implements MessageFilter {
    public static final String NAME = "IPv4 address Anonymizer";
    private static final String REPLACEMENT = "$1.$2.$3.xxx";
    private static final Pattern PATTERN = Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})");

    @Override
    public boolean filter(Message msg) {
        for (Map.Entry<String, Object> a : msg.getFields().entrySet()) {
            if (a.getValue() instanceof String && !"source".equals(a.getKey())) {
                msg.addField(a.getKey(), anonymize((String) a.getValue()));
            }
        }

        // Never filter out a message.
        return false;
    }

    @Override
    public int getPriority() {
        return 0;
    }

    @Override
    public String getName() {
        return NAME;
    }

    private String anonymize(String input) {
        if (isNullOrEmpty(input)) {
            return input;
        }

        return PATTERN.matcher(input).replaceAll(REPLACEMENT);
    }
}