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
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

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
    private LoginContext context;

    public static String getSaslServerFactories() {
        String mechanisms = null;
        Enumeration<SaslServerFactory> serverFactories = Sasl.getSaslServerFactories();
        while (serverFactories.hasMoreElements()) {
            SaslServerFactory serverFactory = serverFactories.nextElement();
            LOGGER.log(Level.INFO, serverFactory.getClass().getName());
            for (String mechanism : serverFactory.getMechanismNames(null)) {
                mechanisms = mechanisms == null ? mechanism : mechanisms + " " + mechanism;
            }
        }
        return mechanisms;
    }

    @Override
    public void init() throws ServletException {
        try {
            context = new LoginContext("server");
            context.login();
            String principals = "Authenticated principals: ";
            for (Principal principal : context.getSubject().getPrincipals()) {
                principals += principal.getName() + " ";
            }
            LOGGER.log(Level.INFO, principals);
        } catch (LoginException ex) {
            Logger.getLogger(SaslServlet.class.getName()).log(Level.SEVERE, null, ex);
            context = null;
        }
    }

    @Override
    public void destroy() {
        try {
            if (context != null) {
                context.logout();
            }
        } catch (LoginException ex) {
            Logger.getLogger(SaslServlet.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private Subject getSubject() {
        return context == null ? null : context.getSubject();
    }

    private static final String getHexBytes(byte[] bytes, int pos, int len) {

        StringBuffer sb = new StringBuffer();
        for (int i = pos; i < (pos+len); i++) {

            int b1 = (bytes[i]>>4) & 0x0f;
            int b2 = bytes[i] & 0x0f;

            sb.append(Integer.toHexString(b1));
            sb.append(Integer.toHexString(b2));
            sb.append(' ');
        }
        return sb.toString();
    }

    private static final String getHexBytes(byte[] bytes) {
        return getHexBytes(bytes, 0, bytes.length);
    }

    public static String bytesToString(byte[] bytes) {
        boolean allAscii = true;
        for (byte b : bytes) {
            if (b < 0x20) {
                allAscii = false;
                break;
            }
        }
        return allAscii ? new String(bytes) : getHexBytes(bytes);
    }

    public static void printBytes(String prompt, byte[] bytes) {
        LOGGER.log(Level.INFO, prompt + ": " + bytesToString(bytes));
    }

    private SaslServer createSaslServer(String mechanism, String serverName) throws SaslException {
        return Sasl.createSaslServer(mechanism, "HTTP", serverName, null, new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                processCallbacks(callbacks);
            }
        });
    }

    class CreateSaslServer implements PrivilegedExceptionAction<SaslServer> {
        private final String mechanism;
        private final String serverName;

        CreateSaslServer(String mechanism, String serverName) {
            this.mechanism = mechanism;
            this.serverName = serverName;
        }

        @Override
        public SaslServer run() throws SaslException {
            return createSaslServer(mechanism, serverName);
        }
    }

    class EvaluateResponse implements PrivilegedExceptionAction<byte[]>{
        private final SaslServer saslServer;
        private final byte[] response;

        public EvaluateResponse(SaslServer saslServer, byte[] response) {
            this.saslServer = saslServer;
            this.response = response;
        }

        @Override
        public byte[] run() throws SaslException {
            return saslServer.evaluateResponse(response);
        }
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
                ((AuthorizeCallback) callback).setAuthorized(true);
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
            printBytes("c2s", c2s);
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
            if (saslServer == null) {
                LOGGER.log(Level.SEVERE, "could not get saslServer from" + s2sBase64);
            } else {
                LOGGER.log(Level.INFO, Integer.toHexString(saslServer.hashCode()));
            }
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

    private static void outputMechs(HttpServletResponse response) throws IOException {
        String serverFactories = getSaslServerFactories();
        response.setHeader("WWW-Authenticate", "SASL mech=\"" + serverFactories + "\",realm=\"" + HTTP_REALM + "\"");
        response.sendError(401, "Unauthorized, SASL Server factories: " + serverFactories);
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
                        try {
                            saslServer = Subject.doAs(
                                getSubject(),
                                new CreateSaslServer(
                                    mechanism,
                                    request.getServerName()
                                )
                            );
                        } catch (PrivilegedActionException ex) {
                            Logger.getLogger(SaslServlet.class.getName()).log(Level.SEVERE, null, ex);
                        }
                        saslServers.put(saslServer.hashCode(), saslServer);
                    }
                    if (saslServer != null) {
                        LOGGER.log(Level.INFO, "not complete");
                        try {
                            byte[] c2s = getc2s(map);
                            challenge = Subject.doAs(getSubject(), new EvaluateResponse(saslServer, c2s));
                            String s2s = SaslServerToS2s(saslServer);
                            String authenticate =
                                "SASL s2s=\"" + s2s+ "\"";
                            if (challenge != null) {
                                challengeBase64 = Base64.getEncoder().encodeToString(challenge);
                                authenticate += ",s2c=\"" + challengeBase64 + "\"";
                            }
                            LOGGER.log(Level.INFO, authenticate);
                            response.setHeader("WWW-Authenticate", authenticate);
                            if (saslServer.isComplete()) {
                                LOGGER.log(Level.INFO, "saslServer complete");
                                sendAnswer(saslServer, request, response, bytesToString(c2s));
                            } else {
                                LOGGER.log(Level.INFO, "saslServer not complete");
                                response.sendError(401, "Unauthorized, challenge: " + new String(challenge, "UTF-8"));
                            }
                        } catch (SaslException ex) {
                            LOGGER.log(Level.SEVERE, ex.getMessage());
                            cleanupSaslService(saslServer);
                            outputMechs(response);
                        } catch (PrivilegedActionException ex) {
                            Logger.getLogger(SaslServlet.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    } else {
                        LOGGER.log(Level.SEVERE, "saslServer is null");
                    }
                } else {
                    LOGGER.log(Level.SEVERE, "map is null");
                }
            } else {
                outputMechs(response);
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
