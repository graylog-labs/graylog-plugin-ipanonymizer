package org.graylog2.filters.ipanonymizer;

import org.graylog2.plugin.Message;
import org.graylog2.plugin.filters.MessageFilter;
import org.joda.time.DateTime;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.endsWith;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class IPAnonymizerFilterTest {

    private final MessageFilter filter = new IPAnonymizerFilter();

    @Test
    public void filterDoesNotFilterOutMessage() throws Exception {
        assertThat(filter.filter(new Message("Hello world!", "localhost", DateTime.now())), is(false));
    }

    @Test
    public void filterAnonymizesIPAddressesInMessage() throws Exception {
        final Message message = new Message("Hello world! 127.0.0.1", "localhost", DateTime.now());
        filter.filter(message);

        assertThat(message.getMessage(), endsWith("127.0.0.xxx"));
    }

    @Test
    public void filterAnonymizesOnlyIPAddresses() throws Exception {
        final Message message = new Message("Hello world! 127/0/0/1", "localhost", DateTime.now());
        filter.filter(message);

        assertThat(message.getMessage(), endsWith("127/0/0/1"));
    }

    @Test
    public void filterAnonymizesIPAddressesInAdditionalFields() throws Exception {
        final Message message = new Message("Hello world!", "localhost", DateTime.now());
        message.addField("my_little_field", "127.0.0.1");
        filter.filter(message);

        assertThat((String) message.getField("my_little_field"), equalTo("127.0.0.xxx"));
    }

    @Test
    public void filterAnonymizesMultipleIPAddresses() throws Exception {
        final Message message = new Message("Hello world! 127.0.0.1 192.168.47.11", "localhost", DateTime.now());
        filter.filter(message);

        assertThat(message.getMessage(), containsString("127.0.0.xxx"));
        assertThat(message.getMessage(), endsWith("192.168.47.xxx"));
    }

    @Test
    public void filterDoesNotAnonymizeSource() throws Exception {
        final Message message = new Message("Hello world!", "127.0.0.1", DateTime.now());
        filter.filter(message);

        assertThat(message.getSource(), equalTo("127.0.0.1"));
    }
}