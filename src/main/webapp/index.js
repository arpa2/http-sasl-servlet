/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
const RE_SASL_MECH = "[A-Z0-9-_]{1,20}";
const RE_MECHSTRING = "\"(" + RE_SASL_MECH + "(?:[ ]" + RE_SASL_MECH + ")*)\"";
const RE_DNSSTRING = "\"([a-zA-Z0-9-_]+(?:\\.[a-zA-Z0-9-_]+)+)\"";

const RE_BWS = "[ \\t]*";
const RE_OWS = RE_BWS;
const RE_TOKEN68 = "([a-zA-Z0-9-._~+/]+=*)";
const RE_AUTH_PARAM =
    "(?:" +
        "([CcSs][2][CcSs])" + RE_BWS + "=" + RE_BWS + RE_TOKEN68 +
        "|" +
        "([Mm][Ee][Cc][Hh])" + RE_BWS + "=" + RE_BWS + RE_MECHSTRING +
        "|" +
        "([Rr][Ee][Aa][Ll][Mm])" + RE_BWS + '=' + RE_BWS + RE_DNSSTRING +
    ")";
const RE_AUTH_SCHEME = "[Ss][Aa][Ss][Ll]";
const RE_CREDENTIALS = RE_AUTH_SCHEME + "(?:[ ]+(" + RE_AUTH_PARAM + "(?:" +
        RE_OWS + "," + RE_OWS + RE_AUTH_PARAM + ")+)?)";



addEventListener("load", function () {
    const parseSasl = function (input) {
        console.log(input);
        console.log(RE_CREDENTIALS);
        const regexp1 = new RegExp(RE_CREDENTIALS);
        if (regexp1.test(input)) {
            console.log(RE_AUTH_PARAM);
            const regexp2 = new RegExp(RE_AUTH_PARAM, "g");
            let result;
            const map = { };
            while (result = regexp2.exec(input)) {
                console.log(result);
                for (let i = 1; i < result.length; i += 2) {
                    if (result[i]) {
                        map[result[i]] = result[i + 1];
                    }
                }
            }
            console.log(map);
        } else {
            console.log("No match");
        }
    }, input_text = document.getElementById("input")
    ;

    document.getElementById("check").addEventListener("click", function () {
        parseSasl(input_text.value);
    }, false);
}, false);
