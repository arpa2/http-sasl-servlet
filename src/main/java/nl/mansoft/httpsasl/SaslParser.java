/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nl.mansoft.httpsasl;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author hfman
 */
public class SaslParser {
    static final String RE_SASL_MECH = "[A-Z0-9-_]{1,20}";
    static final String RE_MECHSTRING = "\"(" + RE_SASL_MECH + "(?:[ ]" + RE_SASL_MECH + ")*)\"";
    // https://stackoverflow.com/a/249937/433626
    static final String RE_REALMSTRING = "\"((?:[^\"\\\\]|\\\\.)*)\""; // "((?:[^"\\]|\\.)*)"

    static final String RE_BWS = "[ \\t]*";
    static final String RE_OWS = RE_BWS;
    static final String RE_BASE64STRING = "\"([a-zA-Z0-9-._~+/]*=*)\"";
    static final String RE_AUTH_PARAM =
        "(?:" +
            "([CcSs][2][CcSs])" + RE_BWS + "=" + RE_BWS + RE_BASE64STRING +
            "|" +
            "([Mm][Ee][Cc][Hh])" + RE_BWS + "=" + RE_BWS + RE_MECHSTRING +
            "|" +
            "([Rr][Ee][Aa][Ll][Mm])" + RE_BWS + '=' + RE_BWS + RE_REALMSTRING +
        ")"
    ;
    static final String RE_AUTH_SCHEME = "[Ss][Aa][Ss][Ll]";
    static final String RE_CREDENTIALS = "^(?:.*,)?[ \\t]*" + RE_AUTH_SCHEME + "(?:[ ]+(" + RE_AUTH_PARAM + "(?:" +
        RE_OWS + "," + RE_OWS + RE_AUTH_PARAM + ")*)?)[ \\t]*(?:,.*)?$";


    public static Map<String, String> parse(String input) {
        Map<String, String> map = null;
        System.out.println(input);
        //String regexp = readRegExp();
        String regexp = RE_CREDENTIALS;
        System.out.println(regexp);
        Pattern authorization_stx = Pattern.compile(regexp);
        Matcher matcher1 = authorization_stx.matcher(input);
        if (matcher1.matches() || true) {
            Pattern auth_param_finder = Pattern.compile(RE_AUTH_PARAM);
            Matcher matcher2 = auth_param_finder.matcher(input);
            map = new HashMap<>();
            while (matcher2.find()) {
                for (int i = 1; i <= matcher2.groupCount(); i += 2) {
                    if (matcher2.group(i) != null) {
                        map.put(matcher2.group(i), matcher2.group(i + 1));
                    }
                }
            }
        }
        return map;
    }
}
