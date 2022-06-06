/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nl.mansoft.httpsasl;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.Security;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
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
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nl.mansoft.security.sasl.Provider;

/**
 *
 * @author hfman
 */
public class SaslServlet extends HttpServlet {
    private static Logger LOGGER = Logger.getLogger(SaslServlet.class.getName());
    private static final String HTTP_REALM = "Java Servlet Realm";
    private Map<Integer, SaslServer> saslServers = new HashMap<>();
    private String name;
    private String text;
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

    @Override
    public void init() {
      Provider provider = new Provider();
      Security.insertProviderAt(provider, 1);
    }

    public static String stringChallengeOrResponse(byte[] data) {
        return data == null ? "(null)" : new String(data);
    }

    public void processCallbacks(Callback[] callbacks) {
        LOGGER.log(Level.INFO, "processCallbacks");
        for (Callback callback : callbacks) {
            LOGGER.log(Level.INFO, callback.getClass().getName());
            if (callback instanceof NameCallback) {
                NameCallback nameCallback = (NameCallback) callback;
                name = nameCallback.getDefaultName();
                LOGGER.log(Level.INFO, name);
                nameCallback.setName(name);
            } else if (callback instanceof PasswordCallback) {
                PasswordCallback passwordCallback = (PasswordCallback) callback;
                passwordCallback.setPassword(new char[] { '1', '2', '3', '4' });
            } else if (callback instanceof RealmCallback) {
                RealmCallback realmCallback = (RealmCallback) callback;
                text = realmCallback.getDefaultText();
                LOGGER.log(Level.INFO, text);
                realmCallback.setText(text);
            } else if (callback instanceof AuthorizeCallback) {
                ((AuthorizeCallback) callback).setAuthorized("henri".equals(name));
            }
        }
    }

    private void sendAnswer(SaslServer saslServer, HttpServletRequest request, HttpServletResponse response, String answer) throws IOException {
        try (PrintWriter out = response.getWriter()) {
            out.println(answer);
        }
        if (cleanupSaslService(saslServer)) {
            LOGGER.log(Level.INFO, "Sasl service was cleaned up");
        }
    }

    private boolean cleanupSaslService(SaslServer saslServer) {
        boolean result = saslServer != null;
        LOGGER.log(Level.INFO, "cleanupSaslService(): SASL service " + (result ? "present" : "not present"));
        try {
            if (result) {
                saslServer.dispose();
                saslServers.remove(saslServer.hashCode());
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

    private int byteToInt(byte b) {
      return b & 0xff;
    }

    private byte intToByte(int i) {
      return (byte) (i & 0xff);
    }

    private Integer bytesToInteger(byte bytes[]) {
      Integer integer = null;
      if (bytes != null && bytes.length == 4) {
        integer = byteToInt(bytes[0]) | byteToInt(bytes[1]) << 8 | byteToInt(bytes[2]) << 16 | byteToInt(bytes[3]) << 24;
      }
      return integer;
    }

    private byte[] integerToBytes(Integer integer) {
      byte bytes[] = null;
      if (integer != null) {
        bytes = new byte[4];
        bytes[0] = intToByte(integer);
        bytes[1] = intToByte(integer >> 8);
        bytes[2] = intToByte(integer >> 16);
        bytes[3] = intToByte(integer >> 24);
      }
      return bytes;
    }

    private SaslServer getSaslServer(Map<String, String> map) {
        SaslServer saslServer = null;
        String s2sBase64 = map.get("s2s");
        if (s2sBase64 != null) {
            LOGGER.log(Level.INFO, s2sBase64);
            byte s2sBytes[] = Base64.getDecoder().decode(s2sBase64);
            saslServer = saslServers.get(bytesToInteger(s2sBytes));
            LOGGER.log(Level.INFO, Integer.toHexString(saslServer.hashCode()));
        } else {
            LOGGER.log(Level.INFO, "s2sBase64 is null");
        }
        return saslServer;
    }

    private String SaslServerToS2s(SaslServer saslServer) {
        LOGGER.log(Level.INFO, Integer.toHexString(saslServer.hashCode()));
        byte s2sBytes[] = integerToBytes(saslServer.hashCode());
        String s2sBase64 = Base64.getEncoder().encodeToString(s2sBytes);
        LOGGER.log(Level.INFO, s2sBase64);
        return s2sBase64;
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
        SaslServer saslServer = null;
        try {
            response.setContentType("text/plain;charset=UTF-8");
            String authorization = request.getHeader("Authorization");
            if (authorization != null) {
                byte[] challenge = null;
                Map<String, String> map = SaslParser.parse(authorization);
                if (map != null) {
                    String challengeBase64 = null;
                    String mechanism = map.get("mech");
                    saslServer = getSaslServer(map);
                    if (saslServer == null) {
                        saslServer = Sasl.createSaslServer(mechanism, "HTTP", request.getServerName(), null, new CallbackHandler() {
                            @Override
                            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                                processCallbacks(callbacks);
                            }
                        });
                        saslServers.put(saslServer.hashCode(), saslServer);
                    }
                    if (saslServer != null) {
                        try {
                            byte[] c2s = getc2s(map);
                            challenge = saslServer.evaluateResponse(c2s);
                            LOGGER.log(Level.INFO, new String(challenge, "UTF-8"));
                            challengeBase64 = Base64.getEncoder().encodeToString(challenge);
                            String s2s = SaslServerToS2s(saslServer);
                            String authenticate =
                                "SASL s2s=\"" + s2s +
                                "\",s2c=\"" + challengeBase64 + "\"";
                            System.out.println(authenticate);
                            response.setHeader("WWW-Authenticate", authenticate);
                            if (saslServer.isComplete()) {
                                LOGGER.log(Level.INFO, "saslServer.isComplete()");
                                sendAnswer(saslServer, request, response, new String(c2s, "UTF-8"));
                            } else {
                                response.sendError(401, "Unauthorized, challenge: " + new String(challenge, "UTF-8"));
                            }
                        } catch (SaslException ex) {
                            LOGGER.log(Level.SEVERE, ex.getMessage());
                            cleanupSaslService(saslServer);
                            response.sendError(401, "Unauthorized, invalid credentials");
                        }
                    } else {
                        System.out.println("saslServer is null");
                    }
                } else {
                    System.out.println("map is null");
                }
            } else {
                String serverFactories = getSaslServerFactories();
                response.setHeader("WWW-Authenticate", "SASL mech=\"" + serverFactories + "\",realm=\"" + HTTP_REALM + "\"");
                response.sendError(401, "Unauthorized, SASL Server factories: " + serverFactories);
            }
        } catch (SaslException ex) {
            LOGGER.log(Level.SEVERE, ex.getMessage());
            cleanupSaslService(saslServer);
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
