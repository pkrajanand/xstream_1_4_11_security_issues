package securityleaks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.converters.ConversionException;
import com.thoughtworks.xstream.security.ForbiddenClassException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Use case (http://x-stream.github.io/CVE-2017-7957.html)
 * --------
 * Pass-in an element for void and watch the app crashes.
 *
 * Fix
 * ---
 * Since v1.4.7, we can force XStream to throw exception to alert on such occasions instead of crashing.
 *
 * Since v1.4.10, XStream would throw exception automatically, instead of crashing, in case encounters such deserialization use cases.
 * However, it broke http://x-stream.github.io/CVE-2013-7285.html again, so v1.4.11 had to be released. In case you are still on a
 * version less than JDKV8, then you will have to pick the hotfix version v1.4.11.1.
 */
public class CVE_2017_7957Tests {

    @Test
    @DisplayName("On success, it should throw XStream ForbiddenClassException Exception")
    void injectVoidAsAnElementWhenDeserializeToPojo() {

        XStream xstream = new XStream();

        /**
         * This requires to avoid XStream to log a warning "Security framework of XStream instance already initialized"
         *
         * An excerpt from XStream 1.4.11 documentation:-
         *
         * This method is a pure helper method for XStream 1.4.x. It initializes an XStream instance with a white list of
         * well-known and simply types of the Java runtime as it is done in XStream 1.5.x by default. This method will do
         * therefore nothing in XStream 1.5.
         *
         */
        XStream.setupDefaultSecurity(xstream);

        ForbiddenClassException forbiddenClassException = assertThrows(ForbiddenClassException.class,
                                                                   ()->{
                         xstream.fromXML("<void/>");
                     }
                     );

        assertThat(forbiddenClassException).hasMessageContaining("void");
    }

    @Test
    @DisplayName("On success, it should throw XStream ForbiddenClassException Exception")
    void injectVoidThroughClassAttributeWhenDeserializeToPojo() {

        XStream xstream = new XStream();
        /**
         * This requires to avoid XStream to log a warning "Security framework of XStream instance already initialized"
         *
         * An excerpt from XStream 1.4.11 documentation:-
         *
         * This method is a pure helper method for XStream 1.4.x. It initializes an XStream instance with a white list of
         * well-known and simply types of the Java runtime as it is done in XStream 1.5.x by default. This method will do
         * therefore nothing in XStream 1.5.
         *
         */
        XStream.setupDefaultSecurity(xstream);

        ForbiddenClassException forbiddenClassException = assertThrows(ForbiddenClassException.class,
                     ()->{
                         xstream.fromXML("<string class='void'>Hello, world!</string>");
                     });
        assertThat(forbiddenClassException).hasMessageContaining("void");
    }

}
