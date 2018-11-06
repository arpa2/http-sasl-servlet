/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nl.mansoft.httpsasl;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 *
 * @author hfman
 */
public class SaslServlet extends HttpServlet {
    private static Logger LOGGER = Logger.getLogger(SaslServlet.class.getName());
    // one SaslServer for now...
    private SaslServer saslServer;

    public static String getSaslServerFactories() {
        String mechanisms = null;
        Enumeration<SaslServerFactory> serverFactories = Sasl.getSaslServerFactories();
        while (serverFactories.hasMoreElements()) {
            SaslServerFactory serverFactory = serverFactories.nextElement();
            System.out.println(serverFactory.getClass().getName());
            for (String mechanism : serverFactory.getMechanismNames(null)) {
                mechanisms = mechanisms == null ? mechanism : mechanisms + " " + mechanism;
            }
        }
        return mechanisms;
    }

    public static String stringChallengeOrResponse(byte[] data) {
        return data == null ? "(null)" : new String(data);
    }

    public static void processCallbacks(Callback[] callbacks) {
        LOGGER.log(Level.INFO, "processCallbacks");
        for (Callback callback : callbacks) {
            LOGGER.log(Level.INFO, callback.getClass().getName());
            if (callback instanceof NameCallback) {
                NameCallback nameCallback = (NameCallback) callback;
                nameCallback.setName(nameCallback.getDefaultName());
            } else if (callback instanceof PasswordCallback) {
                PasswordCallback passwordCallback = (PasswordCallback) callback;
                passwordCallback.setPassword(new char[] { '1', '2', '3', '4' });
            } else if (callback instanceof RealmCallback) {
                RealmCallback realmCallback = (RealmCallback) callback;
                realmCallback.setText(realmCallback.getDefaultText());
            } else if (callback instanceof AuthorizeCallback) {
                ((AuthorizeCallback) callback).setAuthorized(true);
            }
        }
    }

    private void sendAnswer(HttpServletRequest request, HttpServletResponse response, String answer) throws IOException {
        try (PrintWriter out = response.getWriter()) {
            out.println(answer);
        }
        cleanupSaslService();
    }

    private boolean cleanupSaslService() {
        boolean result = saslServer != null;
        LOGGER.log(Level.INFO, "cleanupSaslService(): SASL service " + (result ? "present" : "not present"));
        try {
            if (result) {
                saslServer.dispose();
                saslServer = null;
            }
        } catch (SaslException ex) {
            LOGGER.log(Level.SEVERE, "Error disposing SaslService");
        }
        return result;
    }

    private byte[] getc2s(Map<String, String> map) {
        byte[] c2s = new byte[0];
        String c2sBase64 = map.get("c2s");
        if (c2sBase64 != null) {
            LOGGER.log(Level.INFO, c2sBase64);
            c2s = Base64.getDecoder().decode(c2sBase64);
            LOGGER.log(Level.INFO, new String(c2s));
        } else {
            LOGGER.log(Level.INFO, "c2sBase64 is null");
        }
        return c2s;
    }
    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
     * methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            response.setContentType("text/plain;charset=UTF-8");
            String authorization = request.getHeader("Authorization");
            if (authorization != null) {
                byte[] challenge = null;
                Map<String, String> map = SaslParser.parse(authorization);
                if (map != null) {
                    String challengeBase64 = null;
                    String mechanism = map.get("mech");
                    String realm = map.get("realm");
                    if (mechanism != null && realm != null) {
                        if (saslServer == null) {
                            saslServer = Sasl.createSaslServer(mechanism, "http", realm, null, new CallbackHandler() {
                                @Override
                                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                                    processCallbacks(callbacks);
                                }
                            });
                        }
                        if (saslServer != null) {
                            try {
                                byte[] c2s = getc2s(map);
                                challenge = saslServer.evaluateResponse(c2s);
                                if (saslServer.isComplete()) {
                                    LOGGER.log(Level.INFO, "saslServer.isComplete()");
                                    sendAnswer(request, response, new String(c2s, "UTF-8"));
                                } else {
                                    challengeBase64 = Base64.getEncoder().encodeToString(challenge);
                                    String s2s = "1";
                                    String authenticate =
                                        "SASL mech=\"" + mechanism +
                                        "\",realm=\"" + realm +
                                        "\",s2s=" + s2s +
                                        ",s2c=" + challengeBase64;
                                    System.out.println(authenticate);
                                    response.setHeader("WWW-Authenticate", authenticate);
                                    response.sendError(401, "Unauthorized, challenge: " + new String(challenge, "UTF-8"));

                                }
                            } catch (SaslException ex) {
                                LOGGER.log(Level.SEVERE, ex.getMessage());
                                cleanupSaslService();
                                response.sendError(401, "Unauthorized, invalid credentials");
                            }
                        } else {
                            System.out.println("saslServer is null");
                        }
                    } else {
                        System.out.println("mech or realm is null");
                    }
                } else {
                    System.out.println("map is null");
                }
            } else {
                if (cleanupSaslService()) {
                    LOGGER.log(Level.INFO, "Sasl service was cleaned up");
                } else {
                    String serverFactories = getSaslServerFactories();
                    response.setHeader("WWW-Authenticate", "SASL mech=\"" + serverFactories + "\" realm=\"test-realm.nl\"");
                    response.sendError(401, "Unauthorized, SASL Server factories: " + serverFactories);
                }
            }
        } catch (SaslException ex) {
            LOGGER.log(Level.SEVERE, ex.getMessage());
            cleanupSaslService();
        }
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
