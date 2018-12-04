package securityleaks;

import static org.junit.jupiter.api.Assertions.assertThrows;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.converters.ConversionException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Use case (http://x-stream.github.io/CVE-2013-7285.html)
 * --------
 * Inject code to open an external calculator app while deserializing into POJO.
 *
 * Fix
 * ---
 * It breaches app security to open the calculator until v1.4.6. From v1.4.7 till v1.4.9, it throws an exception saying
 * there is no Converter available for java.beans.EventHandler. Actually this was the fix XStream introduced in v1.4.7 to prevent the issue.
 * Issue again started showing up with v1.4.10 which is fixed with v1.4.10.
 *
 */
public class CVE_2013_7285Tests {

    @Test
    @DisplayName("On success, it should throw XStream Conversion Exception")
    void injectThroughEventHandlerWhenDeserializeToPojo() {

        XStream xstream = new XStream();

        String payload = "<dynamic-proxy>  \n"
            + "<interface>pojo.Contact</interface>  \n"
            + "<handler class=\"java.beans.EventHandler\">  \n"
            + "    <target class=\"java.lang.ProcessBuilder\">\n"
            + "    <command><string>/Applications/Calculator.app/Contents/MacOS/Calculator</string></command>\n"
            + "    </target>\n"
            + "    <action>start</action>\n"
            + "</handler>  \n"
            + "</dynamic-proxy> ";

        assertThrows(ConversionException.class,
                     ()->{
                         xstream.fromXML(payload);
                     });
    }

    @Test
    @DisplayName("On success, it should throw XStream Conversion Exception")
    void injectThroughEventHandlerOnJavaCollectionWhenDeserializeToPojo() {

        XStream xstream = new XStream();

        String payload = "<sorted-set>  \n"
            + "  <string>foo</string>\n"
            + "  <dynamic-proxy>\n"
            + "    <interface>java.lang.Comparable</interface>\n"
            + "    <handler class=\"java.beans.EventHandler\">\n"
            + "      <target class=\"java.lang.ProcessBuilder\">\n"
            + "        <command>\n"
            + "          <string>/Applications/Calculator.app/Contents/MacOS/Calculator</string>\n"
            + "        </command>\n"
            + "      </target>\n"
            + "      <action>start</action>\n"
            + "    </handler>\n"
            + "  </dynamic-proxy>\n"
            + "</sorted-set> ";

        assertThrows(ConversionException.class,
                     ()->{
                         xstream.fromXML(payload);
                     });
    }
}
